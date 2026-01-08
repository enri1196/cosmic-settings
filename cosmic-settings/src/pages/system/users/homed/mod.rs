// Copyright 2024 System76 <info@system76.com>
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::Context;
use pwhash::sha512_crypt;
use std::collections::HashMap;
use std::fs::File;
use std::os::fd::OwnedFd as StdOwnedFd;
use std::time::{SystemTime, UNIX_EPOCH};
use zbus::zvariant::OwnedFd;

use crate::pages::system::users::backend::{UserBackend, UserBackendKind, UserEntry};
use crate::pages::system::users::homed::home1_manager::Home1ManagerProxy;
use crate::pages::system::users::homed::homed_json::{
    UserPrivilegedSection, UserRecord, UserSecretSection,
};

mod home1_manager;
mod homed_json;

pub struct HomedBackend {
    conn: zbus::Connection,
}

const ADMIN_GROUPS: [&str; 2] = ["sudo", "wheel"];

impl HomedBackend {
    pub async fn try_new() -> Option<Self> {
        let conn = zbus::Connection::system().await.ok()?;
        let _proxy = Home1ManagerProxy::new(&conn).await.ok()?;
        Some(Self { conn })
    }

    async fn manager(&self) -> anyhow::Result<Home1ManagerProxy<'_>> {
        Home1ManagerProxy::new(&self.conn)
            .await
            .context("failed to create home1 manager proxy")
    }
}

#[async_trait::async_trait]
impl UserBackend for HomedBackend {
    async fn list_users(&self) -> anyhow::Result<Vec<UserEntry>> {
        let manager = self.manager().await?;
        let homes = manager.list_homes().await.context("failed to list homes")?;

        let mut users = Vec::with_capacity(homes.len());

        for (name, uid, _state, _gid, real_name, _home, _shell, _path) in homes {
            let is_admin = match manager.get_user_record_by_name(name.clone()).await {
                Ok((record_json, _incomplete, _path)) => {
                    let record = parse_user_record(&record_json)?;
                    record_has_admin(&record)
                }
                Err(why) => {
                    tracing::debug!(?why, "failed to read homed user record");
                    false
                }
            };

            users.push(UserEntry {
                id: uid as u64,
                username: name,
                full_name: real_name,
                is_admin,
                profile_icon: None,
                backend: UserBackendKind::Homed,
            });
        }

        Ok(users)
    }

    async fn set_password(
        &self,
        user: &UserEntry,
        password: &str,
        old_password: Option<&str>,
    ) -> anyhow::Result<()> {
        let manager = self.manager().await?;

        let old_password = old_password
            .filter(|p| !p.is_empty())
            .context("homed password updates require the current password")?;

        manager
            .unlock_home(
                user.username.clone(),
                secret_payload(old_password)?,
            )
            .await
            .context("failed to activate home for password change")?;

        manager
            .change_password_home(
                user.username.clone(),
                secret_payload(password)?,
                secret_payload(old_password)?,
            )
            .await
            .context("failed to change homed password")?;

        let (record_json, _incomplete, _path) = manager
            .get_user_record_by_name(user.username.clone())
            .await?;

        let mut record = parse_user_record(&record_json)?;
        sanitize_record_for_update(&mut record);
        bump_last_change(&mut record)?;

        manager
            .update_home(serialize_user_record(&record)?)
            .await?;

        Ok(())
    }

    async fn delete_user(&self, user: &UserEntry) -> anyhow::Result<()> {
        let manager = self.manager().await?;
        manager
            .remove_home(user.username.clone())
            .await
            .context("failed to remove homed user")?;
        Ok(())
    }

    async fn set_admin(
        &self,
        user: &UserEntry,
        is_admin: bool,
        auth_password: Option<&str>,
    ) -> anyhow::Result<()> {
        let manager = self.manager().await?;
        let (record_json, _incomplete, _path) = manager
            .get_user_record_by_name(user.username.clone())
            .await
            .context("failed to look up homed user record")?;
        let mut record = parse_user_record(&record_json)?;

        // sanitize_record_for_update(&mut record)?;

        let changed = update_member_of(&mut record.member_of, is_admin);

        if !changed {
            return Ok(());
        }

        bump_last_change(&mut record)?;

        if let Some(password) = auth_password.filter(|value| !value.is_empty()) {
            insert_password_secret(&mut record, password)?;
            if !record_has_hashed_password(&record) {
                insert_password_hash(&mut record, password)?;
            }
        }

        manager
            .update_home(serialize_user_record(&record)?)
            .await
            .context("failed to update homed user record")?;

        Ok(())
    }

    async fn create_user(
        &self,
        username: &str,
        full_name: &str,
        password: &str,
        is_admin: bool,
    ) -> anyhow::Result<()> {
        let manager = self.manager().await?;
        let password_hash = hash_password(password)?;

        let mut record = UserRecord {
            user_name: Some(username.to_string()),
            ..UserRecord::default()
        };

        if !full_name.is_empty() {
            record.real_name = Some(full_name.to_string());
        }

        record.privileged = Some(UserPrivilegedSection {
            hashed_password: vec![password_hash],
            ..UserPrivilegedSection::default()
        });
        record.secret = Some(UserSecretSection {
            password: vec![password.to_string()],
            ..UserSecretSection::default()
        });

        manager
            .create_home(serialize_user_record(&record)?)
            .await
            .context("failed to create homed user")?;

        if is_admin {
            let (uid, _state, _gid, _real_name, _home, _shell, _path) = manager
                .get_home_by_name(username.to_string())
                .await
                .context("failed to look up homed user")?;
            let entry = UserEntry {
                id: uid as u64,
                username: username.to_string(),
                full_name: full_name.to_string(),
                is_admin,
                profile_icon: None,
                backend: UserBackendKind::Homed,
            };

            self.set_admin(&entry, true, None)
                .await
                .context("failed to set homed user as admin")?;
        }

        Ok(())
    }

    async fn set_full_name(
        &self,
        user: &UserEntry,
        full_name: &str,
        auth_password: Option<&str>,
    ) -> anyhow::Result<()> {
        let manager = self.manager().await?;
        let (record_json, _incomplete, _path) = manager
            .get_user_record_by_name(user.username.clone())
            .await
            .context("failed to look up homed user record")?;
        let mut record = parse_user_record(&record_json)?;

        sanitize_record_for_update(&mut record);

        let current = record.real_name.as_deref().unwrap_or("");
        if current == full_name {
            return Ok(());
        }

        if full_name.is_empty() {
            record.real_name = None;
        } else {
            record.real_name = Some(full_name.to_string());
        }

        bump_last_change(&mut record)?;

        if let Some(password) = auth_password.filter(|value| !value.is_empty()) {
            insert_password_secret(&mut record, password)?;
            if !record_has_hashed_password(&record) {
                insert_password_hash(&mut record, password)?;
            }
        }

        manager
            .update_home(serialize_user_record(&record)?)
            .await
            .context("failed to update homed user record")?;

        Ok(())
    }

    async fn set_username(&self, _user: &UserEntry, _username: &str) -> anyhow::Result<()> {
        anyhow::bail!("systemd-homed does not support renaming users")
    }

    async fn set_profile_icon(
        &self,
        user: &UserEntry,
        icon_path: &std::path::Path,
        auth_password: Option<&str>,
    ) -> anyhow::Result<()> {
        let manager = self.manager().await?;
        let (record_json, _incomplete, _path) = manager
            .get_user_record_by_name(user.username.clone())
            .await
            .context("failed to look up homed user record")?;
        let mut record = parse_user_record(&record_json)?;

        sanitize_record_for_update(&mut record);
        record.extra.remove("blobManifest");

        bump_last_change(&mut record)?;

        if let Some(password) = auth_password.filter(|value| !value.is_empty()) {
            insert_password_secret(&mut record, password)?;
            if !record_has_hashed_password(&record) {
                insert_password_hash(&mut record, password)?;
            }
        }

        let blobs = avatar_blobs(icon_path)?;
        manager
            .update_home_ex(serialize_user_record(&record)?, blobs, 0)
            .await
            .context("failed to update homed user record")?;

        Ok(())
    }
}

#[derive(serde::Serialize)]
struct SecretPayload {
    secret: UserSecretSection,
}

fn parse_user_record(record_json: &str) -> anyhow::Result<UserRecord> {
    serde_json::from_str(record_json).context("failed to parse homed user record")
}

fn serialize_user_record(record: &UserRecord) -> anyhow::Result<String> {
    serde_json::to_string(record).context("failed to serialize homed user record")
}

fn secret_payload(password: &str) -> anyhow::Result<String> {
    let secret = UserSecretSection {
        password: vec![password.to_string()],
        ..UserSecretSection::default()
    };
    serde_json::to_string(&SecretPayload { secret })
        .context("failed to serialize homed secret payload")
}

fn record_has_admin(record: &UserRecord) -> bool {
    record
        .member_of
        .iter()
        .map(String::as_str)
        .any(is_admin_group)
}

fn is_admin_group(group: &str) -> bool {
    ADMIN_GROUPS.iter().any(|admin_group| *admin_group == group)
}

fn update_member_of(member_of: &mut Vec<String>, is_admin: bool) -> bool {
    let mut changed = false;

    if is_admin {
        for admin_group in ADMIN_GROUPS {
            if !member_of.iter().any(|group| group == admin_group) {
                member_of.push(admin_group.to_string());
                changed = true;
            }
        }
    } else {
        let original_len = member_of.len();
        member_of.retain(|group| !is_admin_group(group));
        changed = member_of.len() != original_len;
    }

    changed
}

fn bump_last_change(record: &mut UserRecord) -> anyhow::Result<()> {
    let mut now_us = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before unix epoch")?
        .as_micros();
    if now_us > u128::from(u64::MAX) {
        now_us = u128::from(u64::MAX);
    }
    let mut new_value = now_us as u64;

    if let Some(current) = record.last_change_usec {
        if new_value <= current {
            new_value = current.saturating_add(1);
        }
    }

    record.last_change_usec = Some(new_value);

    Ok(())
}

fn sanitize_record_for_update(record: &mut UserRecord) {
    record.binding.clear();
    record.status.clear();
    record.secret = None;
    record.signature.clear();
}

fn insert_password_secret(record: &mut UserRecord, password: &str) -> anyhow::Result<()> {
    let mut secret = record.secret.take().unwrap_or_default();
    secret.password = vec![password.to_string()];
    record.secret = Some(secret);

    Ok(())
}

fn record_has_hashed_password(record: &UserRecord) -> bool {
    record
        .privileged
        .as_ref()
        .is_some_and(|privileged| !privileged.hashed_password.is_empty())
}

fn insert_password_hash(record: &mut UserRecord, password: &str) -> anyhow::Result<()> {
    let password_hash = hash_password(password)?;
    let privileged = record
        .privileged
        .get_or_insert_with(UserPrivilegedSection::default);
    privileged.hashed_password = vec![password_hash];

    Ok(())
}

fn avatar_blobs(icon_path: &std::path::Path) -> anyhow::Result<HashMap<String, OwnedFd>> {
    let file = File::open(icon_path)
        .with_context(|| format!("failed to open avatar image {}", icon_path.display()))?;
    let metadata = file.metadata().context("failed to read avatar metadata")?;
    if !metadata.is_file() {
        anyhow::bail!("avatar image is not a regular file");
    }

    let owned: StdOwnedFd = file.into();
    let mut blobs = HashMap::new();
    blobs.insert("avatar".to_string(), OwnedFd::from(owned));
    Ok(blobs)
}

fn hash_password(password_plain: &str) -> anyhow::Result<String> {
    sha512_crypt::hash(password_plain).context("failed to hash homed password")
}
