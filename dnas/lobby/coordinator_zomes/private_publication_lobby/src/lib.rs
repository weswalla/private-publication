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
fn grant_capability_to_read(authorized_agent: AgentPubKey) -> ExternResult<CapSecret> {
    let mut assignees: BTreeSet<AgentPubKey> = BTreeSet::new();
    assignees.insert(authorized_agent); // Assign capabilty to the given "authorized_agent"
    let secret = cap_secret()?;
    let access = CapAccess::Assigned {
        // Requests are required to carry this secret and be signed by one of the assignees
        secret,
        assignees,
    };
    let capability_grant = CapGrantEntry {
        functions: functions_to_grant_capability_for()?,
        access,
        tag: String::from("assigned capability"), // Convenience tag
    };

    create_cap_grant(capability_grant)?;

    Ok(secret)
}
fn functions_to_grant_capability_for() -> ExternResult<BTreeSet<(ZomeName, FunctionName)>> {
    // Type required by the HDK API
    let zome_name = zome_info()?.name; // Getting the zome name
    let function_name = FunctionName(String::from("request_read_all_posts")); // Wrapper around a "String"

    let mut functions: BTreeSet<(ZomeName, FunctionName)> = BTreeSet::new();
    functions.insert((zome_name, function_name)); // Granting access to the function in this zome

    Ok(functions)
}

#[hdk_extern]
fn store_capability_claim(secret: CapSecret) -> ExternResult<()> {
    let cap_claim = CapClaimEntry {
        // Built-in private entry
        grantor: progenitor(())?, // Just to remember which agent to call
        secret,                   // Store the secret
        tag: String::from("progenitor_all_posts"), // Can be different from the tag in the grant
    };
    create_cap_claim(cap_claim)?;
    Ok(())
}

fn query_cap_claim_for() -> ExternResult<CapClaim> {
    let cap_claim_entry_type: EntryType = EntryType::CapClaim;
    let filter = ChainQueryFilter::new().entry_type(cap_claim_entry_type).include_entries(true);

    let mut all_my_cap_claims = query(filter)?; // Only the records whose action is of type "CreateLink"
    if all_my_cap_claims.len() < 1 {
        Err(wasm_error!(WasmErrorInner::Guest(String::from(
            "could not find claim in source chain"
        ))))?;
    }
    let claim_record = all_my_cap_claims
        .pop()
        .ok_or(wasm_error!(WasmErrorInner::Guest(String::from(
            "error popping vec of rec, meaning empty"
        ))))?;

    match claim_record.entry {
        RecordEntry::Present(entry) => Ok(entry
            .as_cap_claim()
            .ok_or(wasm_error!(WasmErrorInner::Guest(String::from(
                "could not convert from entry to cap claim"
            ))))?
            .clone()),
        RecordEntry::Hidden => Err(wasm_error!(WasmErrorInner::Guest(String::from(
            "record entry is hidden"
        )))),
        RecordEntry::NotApplicable => Err(wasm_error!(WasmErrorInner::Guest(String::from(
            "record entry is not applicable"
        )))),
        RecordEntry::NotStored => Err(wasm_error!(WasmErrorInner::Guest(String::from(
            "record entry is not stored"
        )))),
    }
    // if let RecordEntry::Present(entry) = claim_record.entry {
    //     Ok(entry
    //         .as_cap_claim()
    //         .ok_or(wasm_error!(WasmErrorInner::Guest(String::from(
    //             "could not convert from entry to cap claim"
    //         ))))?
    //         .clone())
    // } else {
    //     Err(wasm_error!(WasmErrorInner::Guest(String::from(
    //         "could not get entry from record"
    //     ))))
    // }
    // Ok(claim_record
    // .entry
    // .into_option()
    // .ok_or(wasm_error!(WasmErrorInner::Guest(String::from(
    //     "could not get entry from record"
    // ))))?
    // .as_cap_claim()
    // .ok_or(wasm_error!(WasmErrorInner::Guest(String::from(
    //     "could not convert from entry to cap claim"
    // ))))?
    // .clone())
    // let thing = all_my_cap_claims
    //     .iter()
    //     .filter_map(|record| record.clone().entry.into_option())
    //     .filter_map(|entry| entry.clone().as_cap_claim().map(|c| c.clone()))
    //     .collect::<Vec<CapClaim>>().pop().unwrap();
    // .find(|cap_claim| cap_claim.clone().tag == String::from("progenitor_all_posts"))
    // .ok_or(wasm_error!(WasmErrorInner::Guest(String::from(
    //     "no cap claim found"
    // ))))?;
    // Ok(thing.clone())
}
#[hdk_extern]
fn read_all_posts(_: ()) -> ExternResult<Vec<Record>> {
    // Call "callee"'s "zome_function_a" and return its result
    let callee = progenitor(())?;
    let cap_claim_entry: CapClaimEntry = query_cap_claim_for()?; // Assummes the claim was committed in the past

    let zome_call_response = call_remote(
        callee,                                               // Peer in this network we are calling
        zome_info()?.name, // We are calling a function defined in this zome
        FunctionName(String::from("request_read_all_posts")), // Function name
        Some(cap_claim_entry.secret), // Cap secret
        (),
    )?;

    match zome_call_response {
        ZomeCallResponse::Ok(result) => {
            // ExternIO is a wrapper around a byte array
            let post_records: Vec<Record> =
                result.decode().map_err(|err| wasm_error!(err.into()))?; // Deserialize byte array
            Ok(post_records)
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
/** Don't change */
#[cfg(feature = "exercise")]
extern crate private_publication_lobby;
