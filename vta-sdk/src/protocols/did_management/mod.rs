pub mod create;
pub mod delete;
pub mod get;
pub mod list;
pub mod servers;

pub const PROTOCOL_BASE: &str = "https://firstperson.network/protocols/did-management/1.0";

pub const CREATE_DID_WEBVH: &str =
    "https://firstperson.network/protocols/did-management/1.0/create-did-webvh";
pub const CREATE_DID_WEBVH_RESULT: &str =
    "https://firstperson.network/protocols/did-management/1.0/create-did-webvh-result";

pub const GET_DID_WEBVH: &str =
    "https://firstperson.network/protocols/did-management/1.0/get-did-webvh";
pub const GET_DID_WEBVH_RESULT: &str =
    "https://firstperson.network/protocols/did-management/1.0/get-did-webvh-result";

pub const LIST_DIDS_WEBVH: &str =
    "https://firstperson.network/protocols/did-management/1.0/list-dids-webvh";
pub const LIST_DIDS_WEBVH_RESULT: &str =
    "https://firstperson.network/protocols/did-management/1.0/list-dids-webvh-result";

pub const DELETE_DID_WEBVH: &str =
    "https://firstperson.network/protocols/did-management/1.0/delete-did-webvh";
pub const DELETE_DID_WEBVH_RESULT: &str =
    "https://firstperson.network/protocols/did-management/1.0/delete-did-webvh-result";

pub const ADD_WEBVH_SERVER: &str =
    "https://firstperson.network/protocols/did-management/1.0/add-webvh-server";
pub const ADD_WEBVH_SERVER_RESULT: &str =
    "https://firstperson.network/protocols/did-management/1.0/add-webvh-server-result";

pub const LIST_WEBVH_SERVERS: &str =
    "https://firstperson.network/protocols/did-management/1.0/list-webvh-servers";
pub const LIST_WEBVH_SERVERS_RESULT: &str =
    "https://firstperson.network/protocols/did-management/1.0/list-webvh-servers-result";

pub const UPDATE_WEBVH_SERVER: &str =
    "https://firstperson.network/protocols/did-management/1.0/update-webvh-server";
pub const UPDATE_WEBVH_SERVER_RESULT: &str =
    "https://firstperson.network/protocols/did-management/1.0/update-webvh-server-result";

pub const REMOVE_WEBVH_SERVER: &str =
    "https://firstperson.network/protocols/did-management/1.0/remove-webvh-server";
pub const REMOVE_WEBVH_SERVER_RESULT: &str =
    "https://firstperson.network/protocols/did-management/1.0/remove-webvh-server-result";
