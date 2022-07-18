use ::hdk::prelude::*;
use hdk::prelude::holo_hash::AgentPubKeyB64;

#[derive(Serialize, Deserialize, Debug, SerializedBytes)]
struct Properties {
    progenitor: AgentPubKeyB64,
}

#[hdk_extern]
fn progenitor(_: ()) -> ExternResult<AgentPubKey> {
    let dna_info = dna_info()?.properties;
    let progenitor =
        Properties::try_from(dna_info).map_err(|e| wasm_error!(WasmErrorInner::Guest(e.into())))?;
    Ok(progenitor.progenitor.into())
}

#[hdk_extern]
fn request_read_all_posts(_: ()) -> ExternResult<Vec<Record>> {
    let response = call(
        CallTargetCell::OtherRole(String::from("private_publication")),
        ZomeName::from(String::from("posts")),
        FunctionName::from(String::from("get_all_posts")),
        None,
        (),
    )?;
    match response {
        ZomeCallResponse::Ok(result) => {
            // ExternIO is a wrapper around a byte array
            let records: Vec<Record> = result.decode().map_err(|err| wasm_error!(err.into()))?; // Deserialize byte array
            Ok(records)
        }
        ZomeCallResponse::Unauthorized(_, _, _, _) => {
            // Callee deleted the capability grant
            Err(wasm_error!(WasmErrorInner::Guest(
                "Agent revoked the capability".into()
            )))
        }
        ZomeCallResponse::NetworkError(err) => {
            // Network error, we could try again
            Err(wasm_error!(WasmErrorInner::Guest(format!(
                "There was a network error: {:?}",
                err
            ))))
        }
        ZomeCallResponse::CountersigningSession(err) => Err(wasm_error!(WasmErrorInner::Guest(
            format!("There was a network error: {:?}", err)
        ))),
    }
}

// Which secret do they need to know to call those functions?
fn cap_secret() -> ExternResult<CapSecret> {
    // Wrapper around a byte array
    let bytes = random_bytes(64)?;
    let secret = CapSecret::try_from(bytes.into_vec())
        .map_err(|_| wasm_error!(WasmErrorInner::Guest("Could not build secret".into())))?;

    Ok(secret)
}
#[hdk_extern]
fn grant_capability_to_read(authorized_agent: AgentPubKey) -> ExternResult<()> {
    let mut assignees: BTreeSet<AgentPubKey> = BTreeSet::new();
    assignees.insert(authorized_agent); // Assign capabilty to the given "authorized_agent"

    let access = CapAccess::Assigned {
        // Requests are required to carry this secret and be signed by one of the assignees
        secret: cap_secret()?,
        assignees,
    };
    let capability_grant = CapGrantEntry {
        functions: functions_to_grant_capability_for()?,
        access,
        tag: String::from("assigned capability"), // Convenience tag
    };

    create_cap_grant(capability_grant)?;

    Ok(())
}
fn functions_to_grant_capability_for() -> ExternResult<BTreeSet<(ZomeName, FunctionName)>> { // Type required by the HDK API
    let zome_name = zome_info()?.name; // Getting the zome name
    let function_name = FunctionName(String::from("request_read_all_posts")); // Wrapper around a "String"
  
    let mut functions: BTreeSet<(ZomeName, FunctionName)> = BTreeSet::new();
    functions.insert((zome_name, function_name)); // Granting access to the function in this zome
  
    Ok(functions)
}
/** Don't change */
#[cfg(feature = "exercise")]
extern crate private_publication_lobby;
