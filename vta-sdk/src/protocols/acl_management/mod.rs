pub mod create;
pub mod delete;
pub mod get;
pub mod list;
pub mod update;

pub const PROTOCOL_BASE: &str = "https://firstperson.network/protocols/acl-management/1.0";

pub const CREATE_ACL: &str = "https://firstperson.network/protocols/acl-management/1.0/create-acl";
pub const CREATE_ACL_RESULT: &str =
    "https://firstperson.network/protocols/acl-management/1.0/create-acl-result";

pub const GET_ACL: &str = "https://firstperson.network/protocols/acl-management/1.0/get-acl";
pub const GET_ACL_RESULT: &str =
    "https://firstperson.network/protocols/acl-management/1.0/get-acl-result";

pub const LIST_ACL: &str = "https://firstperson.network/protocols/acl-management/1.0/list-acl";
pub const LIST_ACL_RESULT: &str =
    "https://firstperson.network/protocols/acl-management/1.0/list-acl-result";

pub const UPDATE_ACL: &str = "https://firstperson.network/protocols/acl-management/1.0/update-acl";
pub const UPDATE_ACL_RESULT: &str =
    "https://firstperson.network/protocols/acl-management/1.0/update-acl-result";

pub const DELETE_ACL: &str = "https://firstperson.network/protocols/acl-management/1.0/delete-acl";
pub const DELETE_ACL_RESULT: &str =
    "https://firstperson.network/protocols/acl-management/1.0/delete-acl-result";
