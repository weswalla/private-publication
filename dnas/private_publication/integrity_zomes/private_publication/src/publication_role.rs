use crate::properties::progenitor;
use hdi::prelude::*;
pub use crate::validation::EntryTypes;

#[hdk_entry_helper]
pub struct PublicationRole {
    pub role: String,
    pub assignee: AgentPubKey,
}
// #[hdk_entry_defs]
// #[unit_enum(UnitTypes)]
// pub enum EntryTypes {
//     PublicationRole(PublicationRole),
// }

pub fn validate_create_role(
    action: EntryCreationAction,
    role_entry: Entry,
) -> ExternResult<ValidateCallbackResult> {
    // Ok(ValidateCallbackResult::Valid)
    if action.author().clone() == progenitor()? {
        Ok(ValidateCallbackResult::Valid)
    }
    else {
        Ok(ValidateCallbackResult::Invalid(String::from("author does not match progenitor")))
    }
}
