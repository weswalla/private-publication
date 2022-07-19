use hdi::prelude::*;
use crate::{properties::progenitor, *};
use crate::publication_role::PublicationRole;

#[hdk_entry_helper]
pub struct Post {
    pub title: String,
    pub content: String,
}

pub fn validate_create_post(action: EntryCreationAction) -> ExternResult<ValidateCallbackResult> {
    // Ok(ValidateCallbackResult::Valid)
    let author = action.author().clone();
    if author == progenitor()? {
        Ok(ValidateCallbackResult::Valid)
    }
    else {
        let publication_role = PublicationRole {
            role: String::from("editor"),
            assignee: author,
        };
        must_get_entry(hash_entry(publication_role)?)?;
        Ok(ValidateCallbackResult::Valid)
    }
}

pub fn validate_update_post(
    original_action: EntryCreationAction,
    original_entry: Entry,
    action: Update,
    new_entry: Entry,
) -> ExternResult<ValidateCallbackResult> {
    Ok(ValidateCallbackResult::Valid)
}
