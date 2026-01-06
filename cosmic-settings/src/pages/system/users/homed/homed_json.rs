use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

// Records generated from docs https://systemd.io/USER_RECORD/ using LLM

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UserRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(rename = "uid", skip_serializing_if = "Option::is_none")]
    pub uid: Option<u64>,
    #[serde(rename = "gid", skip_serializing_if = "Option::is_none")]
    pub gid: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub real_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home_directory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub member_of: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposition: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(rename = "lastChangeUSec", skip_serializing_if = "Option::is_none")]
    pub last_change_usec: Option<u64>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub environment: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileged: Option<UserPrivilegedSection>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub per_machine: Vec<UserPerMachineSection>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub binding: HashMap<String, UserBindingSection>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub status: HashMap<String, UserStatusSection>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signature: Vec<UserSignatureSection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<UserSecretSection>,
    #[serde(flatten, default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UserPrivilegedSection {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hashed_password: Vec<String>,
    #[serde(rename = "passwordChangeUSec", skip_serializing_if = "Option::is_none")]
    pub password_change_usec: Option<u64>,
    #[serde(rename = "passwordExpireUSec", skip_serializing_if = "Option::is_none")]
    pub password_expire_usec: Option<u64>,
    #[serde(flatten, default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UserPerMachineSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_machine_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nice: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_weight: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_weight: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_max: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tasks_max: Option<u64>,
    #[serde(flatten, default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UserBindingSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supplementary_gids: Vec<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home_directory: Option<String>,
    #[serde(flatten, default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UserStatusSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(rename = "lastLoginUSec", skip_serializing_if = "Option::is_none")]
    pub last_login_usec: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_usage: Option<u64>,
    #[serde(flatten, default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UserSignatureSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(flatten, default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UserSecretSection {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub password: Vec<String>,
    #[serde(flatten, default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GroupRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(rename = "gid", skip_serializing_if = "Option::is_none")]
    pub gid: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposition: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(rename = "lastChangeUSec", skip_serializing_if = "Option::is_none")]
    pub last_change_usec: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub administrators: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileged: Option<GroupPrivilegedSection>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub per_machine: Vec<GroupPerMachineSection>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub binding: HashMap<String, GroupBindingSection>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub status: HashMap<String, GroupStatusSection>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signature: Vec<GroupSignatureSection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<GroupSecretSection>,
    #[serde(flatten, default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GroupPrivilegedSection {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hashed_password: Vec<String>,
    #[serde(flatten, default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GroupPerMachineSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_machine_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_hostname: Option<String>,
    #[serde(rename = "gid", skip_serializing_if = "Option::is_none")]
    pub gid: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub administrators: Vec<String>,
    #[serde(flatten, default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GroupBindingSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u64>,
    #[serde(flatten, default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GroupStatusSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(flatten, default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GroupSignatureSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(flatten, default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GroupSecretSection {
    #[serde(flatten, default, skip_serializing_if = "HashMap::is_empty")]
    pub entries: HashMap<String, Value>,
}
