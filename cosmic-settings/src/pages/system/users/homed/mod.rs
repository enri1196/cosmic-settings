// Copyright 2024 System76 <info@system76.com>
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::Context;
use pwhash::sha512_crypt;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs::File;
use std::os::fd::OwnedFd as StdOwnedFd;
use std::time::{SystemTime, UNIX_EPOCH};
use zbus::zvariant::OwnedFd;

use crate::pages::system::users::backend::{UserBackend, UserBackendKind, UserEntry};
use crate::pages::system::users::homed::home1_manager::Home1ManagerProxy;

mod home1_manager;

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
                    let record: Value = serde_json::from_str(&record_json)
                        .context("failed to parse homed user record")?;
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
            .filter(|value| !value.is_empty())
            .context("homed password updates require the current password")?;
        let (record_json, _incomplete, _path) = manager
            .get_user_record_by_name(user.username.clone())
            .await
            .context("failed to look up homed user record")?;
        let mut record: Value =
            serde_json::from_str(&record_json).context("failed to parse homed user record")?;

        sanitize_record_for_update(&mut record)?;
        insert_password_hash(&mut record, password)?;
        insert_password_secret(&mut record, old_password)?;
        bump_last_change(&mut record)?;

        manager
            .update_home(record.to_string())
            .await
            .context("failed to update homed user record")?;

        let new_secret = json!({"secret": {"password": [password]}}).to_string();
        let old_secret = json!({"secret": {"password": [old_password]}}).to_string();

        manager
            .change_password_home(
                user.username.to_string(),
                new_secret.to_string(),
                old_secret.to_string(),
            )
            .await
            .context("failed to change password with interactive auth")?;

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
        let mut record: Value =
            serde_json::from_str(&record_json).context("failed to parse homed user record")?;

        sanitize_record_for_update(&mut record)?;

        let member_of = member_of_from_record(&record);
        let (member_of, changed) = update_member_of(member_of, is_admin);

        if !changed {
            return Ok(());
        }

        bump_last_change(&mut record)?;

        let Some(record_obj) = record.as_object_mut() else {
            anyhow::bail!("homed user record is not a JSON object");
        };

        if member_of.is_empty() {
            record_obj.remove("memberOf");
        } else {
            record_obj.insert("memberOf".to_string(), json!(member_of));
        }

        if let Some(password) = auth_password.filter(|value| !value.is_empty()) {
            insert_password_secret(&mut record, password)?;
            if !record_has_hashed_password(&record) {
                insert_password_hash(&mut record, password)?;
            }
        }

        manager
            .update_home(record.to_string())
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
        let mut record = json!({"userName": username});
        let password_hash = hash_password(password)?;

        if !full_name.is_empty() {
            record["realName"] = json!(full_name);
        }

        record["privileged"] = json!({"hashedPassword": [password_hash]});
        record["secret"] = json!({"password": [password]});

        manager
            .create_home(record.to_string())
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
        let mut record: Value =
            serde_json::from_str(&record_json).context("failed to parse homed user record")?;

        sanitize_record_for_update(&mut record)?;

        let Some(record_obj) = record.as_object_mut() else {
            anyhow::bail!("homed user record is not a JSON object");
        };

        let current = record_obj
            .get("realName")
            .and_then(Value::as_str)
            .unwrap_or("");
        if current == full_name {
            return Ok(());
        }

        if full_name.is_empty() {
            record_obj.remove("realName");
        } else {
            record_obj.insert("realName".to_string(), json!(full_name));
        }

        bump_last_change(&mut record)?;

        if let Some(password) = auth_password.filter(|value| !value.is_empty()) {
            insert_password_secret(&mut record, password)?;
            if !record_has_hashed_password(&record) {
                insert_password_hash(&mut record, password)?;
            }
        }

        manager
            .update_home(record.to_string())
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
        let mut record: Value =
            serde_json::from_str(&record_json).context("failed to parse homed user record")?;

        sanitize_record_for_update(&mut record)?;

        let Some(record_obj) = record.as_object_mut() else {
            anyhow::bail!("homed user record is not a JSON object");
        };
        record_obj.remove("blobManifest");

        bump_last_change(&mut record)?;

        if let Some(password) = auth_password.filter(|value| !value.is_empty()) {
            insert_password_secret(&mut record, password)?;
            if !record_has_hashed_password(&record) {
                insert_password_hash(&mut record, password)?;
            }
        }

        let blobs = avatar_blobs(icon_path)?;
        manager
            .update_home_ex(record.to_string(), blobs, 0)
            .await
            .context("failed to update homed user record")?;

        Ok(())
    }
}

fn record_has_admin(record: &Value) -> bool {
    let Some(member_of) = record.get("memberOf").and_then(Value::as_array) else {
        return false;
    };

    member_of
        .iter()
        .filter_map(Value::as_str)
        .any(is_admin_group)
}

fn is_admin_group(group: &str) -> bool {
    ADMIN_GROUPS.iter().any(|admin_group| *admin_group == group)
}

fn member_of_from_record(record: &Value) -> Vec<String> {
    record
        .get("memberOf")
        .and_then(Value::as_array)
        .map(|member_of| {
            member_of
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn update_member_of(mut member_of: Vec<String>, is_admin: bool) -> (Vec<String>, bool) {
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

    (member_of, changed)
}

fn bump_last_change(record: &mut Value) -> anyhow::Result<()> {
    let Some(record_obj) = record.as_object_mut() else {
        anyhow::bail!("homed user record is not a JSON object");
    };

    let mut now_us = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before unix epoch")?
        .as_micros();
    if now_us > u128::from(u64::MAX) {
        now_us = u128::from(u64::MAX);
    }
    let mut new_value = now_us as u64;

    if let Some(current) = record_obj.get("lastChangeUSec").and_then(Value::as_u64) {
        if new_value <= current {
            new_value = current.saturating_add(1);
        }
    }

    record_obj.insert("lastChangeUSec".to_string(), json!(new_value));

    Ok(())
}

fn sanitize_record_for_update(record: &mut Value) -> anyhow::Result<()> {
    let Some(record_obj) = record.as_object_mut() else {
        anyhow::bail!("homed user record is not a JSON object");
    };

    record_obj.remove("binding");
    record_obj.remove("status");
    record_obj.remove("secret");
    record_obj.remove("signature");

    Ok(())
}

fn insert_password_secret(record: &mut Value, password: &str) -> anyhow::Result<()> {
    let Some(record_obj) = record.as_object_mut() else {
        anyhow::bail!("homed user record is not a JSON object");
    };

    record_obj.insert("secret".to_string(), json!({"password": [password]}));

    Ok(())
}

fn record_has_hashed_password(record: &Value) -> bool {
    record
        .get("privileged")
        .and_then(Value::as_object)
        .and_then(|privileged| privileged.get("hashedPassword"))
        .and_then(Value::as_array)
        .is_some_and(|hashes| !hashes.is_empty())
}

fn insert_password_hash(record: &mut Value, password: &str) -> anyhow::Result<()> {
    let password_hash = hash_password(password)?;
    let Some(record_obj) = record.as_object_mut() else {
        anyhow::bail!("homed user record is not a JSON object");
    };

    let privileged = record_obj
        .entry("privileged".to_string())
        .or_insert_with(|| json!({}));
    let Some(privileged_obj) = privileged.as_object_mut() else {
        anyhow::bail!("homed user record privileged section is not a JSON object");
    };

    privileged_obj.insert("hashedPassword".to_string(), json!([password_hash]));

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
