pub mod get_config;
pub mod restart;
pub mod update_config;

pub const PROTOCOL_BASE: &str = "https://firstperson.network/protocols/vta-management/1.0";

pub const GET_CONFIG: &str = "https://firstperson.network/protocols/vta-management/1.0/get-config";
pub const GET_CONFIG_RESULT: &str =
    "https://firstperson.network/protocols/vta-management/1.0/get-config-result";

pub const UPDATE_CONFIG: &str =
    "https://firstperson.network/protocols/vta-management/1.0/update-config";
pub const UPDATE_CONFIG_RESULT: &str =
    "https://firstperson.network/protocols/vta-management/1.0/update-config-result";

pub const RESTART: &str = "https://firstperson.network/protocols/vta-management/1.0/restart";
pub const RESTART_RESULT: &str =
    "https://firstperson.network/protocols/vta-management/1.0/restart-result";
