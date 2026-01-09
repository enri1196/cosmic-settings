// Copyright 2024 System76 <info@system76.com>
// SPDX-License-Identifier: GPL-3.0-only

use async_trait::async_trait;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;
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

#[derive(Clone, Default)]
pub struct BackendRegistry {
    by_kind: HashMap<UserBackendKind, Arc<dyn UserBackend>>,
}

impl std::fmt::Debug for BackendRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendRegistry")
            .field("kinds", &self.by_kind.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl BackendRegistry {
    pub async fn load() -> Self {
        let mut by_kind: HashMap<UserBackendKind, Arc<dyn UserBackend>> = HashMap::new();

        #[cfg(feature = "homed")]
        if let Some(homed) = HomedBackend::try_new().await {
            by_kind.insert(UserBackendKind::Homed, Arc::new(homed));
        }

        if let Some(classic) = ClassicBackend::try_new().await {
            by_kind.insert(UserBackendKind::Homed, Arc::new(classic));
        }

        Self { by_kind }
    }

    pub fn get(&self, kind: UserBackendKind) -> Option<Arc<dyn UserBackend>> {
        self.by_kind.get(&kind).cloned()
    }

    pub fn preferred(&self) -> Option<Arc<dyn UserBackend>> {
        self.get(UserBackendKind::Homed)
            .or_else(|| self.get(UserBackendKind::Classic))
    }

    pub fn homed_available(&self) -> bool {
        self.by_kind.contains_key(&UserBackendKind::Homed)
    }

    pub fn iter(&self) -> impl Iterator<Item = Arc<dyn UserBackend>> + '_ {
        self.by_kind.values().cloned()
    }
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
