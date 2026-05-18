use serde::{Deserialize, Serialize};

pub const CORE_SERVICE_PATHS: [&str; 2] = [
    "/lib/systemd/system/nat.service",
    "/etc/systemd/system/nat.service",
];
pub const NAT_BINARY: &str = "/usr/local/bin/nat";
pub const CONFIG_TOML: &str = "/etc/nat.toml";
pub const CONFIG_LEGACY: &str = "/etc/nat.conf";
pub const STATS_JSON: &str = "/var/lib/nftables-nat-rust/stats.json";
pub const STATS_DIR: &str = "/var/lib/nftables-nat-rust";
pub const BACKUPS_DIR: &str = "/etc/nftables-nat/backups";
pub const BACKUPS_ROOT: &str = "/etc/nftables-nat";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UninstallTarget {
    Core,
    NftTables,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum DataMode {
    #[default]
    Keep,
    KeepConfig,
    Purge,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UninstallPlan {
    pub actions: Vec<String>,
    pub kept: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn validate_uninstall_request(
    target: UninstallTarget,
    data_mode: DataMode,
    confirm: Option<&str>,
) -> Result<(), String> {
    if data_mode == DataMode::Purge && confirm != Some("DELETE") {
        return Err("data_mode=purge requires confirm=DELETE".to_string());
    }
    if target == UninstallTarget::NftTables && data_mode != DataMode::Keep {
        return Err("target=nft-tables only supports data_mode=keep".to_string());
    }
    Ok(())
}

pub fn plan_uninstall(target: UninstallTarget, data_mode: DataMode) -> UninstallPlan {
    let mut plan = UninstallPlan::default();
    if matches!(target, UninstallTarget::Core) {
        plan.actions.extend([
            "stop nat.service".to_string(),
            "disable nat.service".to_string(),
            "remove nat.service".to_string(),
            format!("remove {NAT_BINARY}"),
        ]);
    }
    if matches!(target, UninstallTarget::Core | UninstallTarget::NftTables) {
        plan.actions.extend(
            nft_table_names().map(|(family, table)| format!("delete nft table {family} {table}")),
        );
    }

    match data_mode {
        DataMode::Keep => {
            plan.kept.extend(kept_data_paths());
        }
        DataMode::KeepConfig => {
            plan.kept
                .extend([CONFIG_TOML.to_string(), BACKUPS_DIR.to_string()]);
            plan.actions.extend([
                format!("remove {CONFIG_LEGACY} if selected"),
                format!("remove {STATS_JSON}"),
            ]);
        }
        DataMode::Purge => {
            plan.actions.extend([
                format!("remove {CONFIG_TOML}"),
                format!("remove {CONFIG_LEGACY}"),
                format!("remove {STATS_DIR}"),
                format!("remove {BACKUPS_ROOT}"),
            ]);
            plan.warnings
                .push("purge deletes project config, stats, and backups".to_string());
        }
    }
    plan
}

pub fn kept_data_paths() -> Vec<String> {
    vec![
        CONFIG_TOML.to_string(),
        CONFIG_LEGACY.to_string(),
        STATS_JSON.to_string(),
        BACKUPS_DIR.to_string(),
    ]
}

pub fn nft_table_names() -> impl Iterator<Item = (&'static str, &'static str)> {
    [
        ("ip", "self-nat"),
        ("ip6", "self-nat"),
        ("ip", "self-filter"),
        ("ip6", "self-filter"),
    ]
    .into_iter()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_core_uninstall_without_flush_ruleset() {
        let plan = plan_uninstall(UninstallTarget::Core, DataMode::Keep);
        assert!(
            plan.actions
                .iter()
                .any(|action| action == "stop nat.service")
        );
        assert!(
            plan.actions
                .iter()
                .any(|action| action.contains("delete nft table ip self-nat"))
        );
        assert!(
            plan.actions
                .iter()
                .all(|action| !action.contains("flush ruleset"))
        );
        assert!(plan.kept.contains(&CONFIG_TOML.to_string()));
    }

    #[test]
    fn nft_tables_target_only_deletes_self_tables() {
        let plan = plan_uninstall(UninstallTarget::NftTables, DataMode::Keep);
        assert_eq!(plan.actions.len(), 4);
        assert!(plan.actions.iter().all(|action| action.contains("self-")));
    }

    #[test]
    fn purge_requires_delete_confirmation() {
        assert!(validate_uninstall_request(UninstallTarget::Core, DataMode::Purge, None).is_err());
        assert!(
            validate_uninstall_request(UninstallTarget::Core, DataMode::Purge, Some("DELETE"))
                .is_ok()
        );
    }
}
