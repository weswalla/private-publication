use hdk::prelude::*;
// use private_publication_integrity
use private_publication_integrity::publication_role::{PublicationRole, EntryTypes};


#[hdk_extern]
fn assign_editor_role(assignee: AgentPubKey) -> ExternResult<ActionHash> {
    create_entry(EntryTypes::PublicationRole(PublicationRole {
        assignee,
        role: String::from("editor"),
    }))
}

// /** Don't change */
// #[cfg(not(feature = "exercise2"))]
// extern crate roles;
