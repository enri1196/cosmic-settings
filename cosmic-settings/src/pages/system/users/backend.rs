// Copyright 2024 System76 <info@system76.com>
// SPDX-License-Identifier: GPL-3.0-only

use async_trait::async_trait;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use zbus_polkit::policykit1::CheckAuthorizationFlags;

pub use super::classic::ClassicBackend;
#[cfg(feature = "homed")]
pub use super::homed::HomedBackend;

const USERS_ADMIN_POLKIT_POLICY_ID: &str = "com.system76.CosmicSettings.Users.Admin";

#[derive(Clone, Debug)]
pub struct UserEntry {
    pub id: u64,
    pub username: String,
    pub full_name: String,
    pub is_admin: bool,
    pub profile_icon: Option<PathBuf>,
    pub backend: UserBackendKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
pub enum UserBackendKind {
    #[default]
    Classic,
    Homed,
}

#[async_trait]
pub trait UserBackend: Send + Sync {
    async fn list_users(&self) -> anyhow::Result<Vec<UserEntry>>;
    async fn set_password(
        &self,
        user: &UserEntry,
        password: &str,
        old_password: Option<&str>,
    ) -> anyhow::Result<()>;
    async fn delete_user(&self, user: &UserEntry) -> anyhow::Result<()>;
    async fn set_admin(
        &self,
        user: &UserEntry,
        is_admin: bool,
        auth_password: Option<&str>,
    ) -> anyhow::Result<()>;
    async fn create_user(
        &self,
        username: &str,
        full_name: &str,
        password: &str,
        is_admin: bool,
    ) -> anyhow::Result<()>;
    async fn set_full_name(
        &self,
        user: &UserEntry,
        full_name: &str,
        auth_password: Option<&str>,
    ) -> anyhow::Result<()>;
    async fn set_username(&self, user: &UserEntry, username: &str) -> anyhow::Result<()>;
    async fn set_profile_icon(
        &self,
        user: &UserEntry,
        icon_path: &Path,
        auth_password: Option<&str>,
    ) -> anyhow::Result<()>;
}

pub async fn active_backends() -> Vec<Box<dyn UserBackend>> {
    let mut backends: Vec<Box<dyn UserBackend>> = Vec::new();

    #[cfg(feature = "homed")]
    if let Some(homed) = HomedBackend::try_new().await {
        backends.push(Box::new(homed));
    }

    backends.push(Box::new(ClassicBackend::new()));

    backends
}

pub async fn backend_for_kind(kind: UserBackendKind) -> Option<Box<dyn UserBackend>> {
    match kind {
        UserBackendKind::Classic => Some(Box::new(ClassicBackend::new())),
        UserBackendKind::Homed => {
            #[cfg(feature = "homed")]
            {
                let Some(homed) = HomedBackend::try_new().await else {
                    return None;
                };
                Some(Box::new(homed))
            }

            #[cfg(not(feature = "homed"))]
            {
                None
            }
        }
    }
}

pub async fn preferred_backend() -> Option<Box<dyn UserBackend>> {
    #[cfg(feature = "homed")]
    if let Some(homed) = HomedBackend::try_new().await {
        return Some(Box::new(homed));
    }

    Some(Box::new(ClassicBackend::new()))
}

pub fn uid_range() -> (u64, u64) {
    let (mut min, mut max) = (1000, 60000);
    let Ok(file) = File::open("/etc/login.defs") else {
        return (min, max);
    };

    let mut reader = BufReader::new(file);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            _ => (),
        }

        let line = line.trim();

        let variable = if line.starts_with("UID_MIN ") {
            &mut min
        } else if line.starts_with("UID_MAX ") {
            &mut max
        } else {
            continue;
        };

        if let Some(value) = line
            .split_ascii_whitespace()
            .nth(1)
            .and_then(|value| value.parse::<u64>().ok())
        {
            *variable = value;
        }
    }

    (min, max)
}

pub async fn request_permission_on_denial<T, Fun, Fut>(
    conn: &zbus::Connection,
    action: Fun,
) -> zbus::Result<T>
where
    Fun: Fn() -> Fut,
    Fut: Future<Output = zbus::Result<T>>,
{
    match action().await {
        Ok(value) => Ok(value),
        Err(why) => {
            if permission_was_denied(&why) {
                _ = check_authorization(conn).await;
                action().await
            } else {
                Err(why)
            }
        }
    }
}

async fn check_authorization(conn: &zbus::Connection) -> anyhow::Result<()> {
    let proxy = zbus_polkit::policykit1::AuthorityProxy::new(conn).await?;
    let subject = zbus_polkit::policykit1::Subject::new_for_owner(std::process::id(), None, None)?;
    proxy
        .check_authorization(
            &subject,
            USERS_ADMIN_POLKIT_POLICY_ID,
            &HashMap::new(),
            CheckAuthorizationFlags::AllowUserInteraction.into(),
            "",
        )
        .await?;
    Ok(())
}

fn permission_was_denied(result: &zbus::Error) -> bool {
    matches!(result, zbus::Error::MethodError(name, _, _) if name.as_str() == "org.freedesktop.Accounts.Error.PermissionDenied")
}
