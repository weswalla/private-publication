use::hdk::prelude::*;
use hdk::prelude::holo_hash::AgentPubKeyB64;

#[derive(Serialize, Deserialize, Debug, SerializedBytes)]
struct Properties {
    progenitor: AgentPubKeyB64,
}

#[hdk_extern]
fn progenitor(_: ()) -> ExternResult<AgentPubKey> {
    let dna_info = dna_info()?.properties;
    let progenitor = Properties::try_from(dna_info).map_err(|e| wasm_error!(WasmErrorInner::Guest(e.into())))?;
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
        ZomeCallResponse::Ok(result) => { // ExternIO is a wrapper around a byte array
          let records: Vec<Record> = result.decode().map_err(|err| wasm_error!(err.into()))?; // Deserialize byte array
          Ok(records)
        },
        ZomeCallResponse::Unauthorized(_,_,_,_) => { // Callee deleted the capability grant
          Err(wasm_error!(WasmErrorInner::Guest("Agent revoked the capability".into())))
        },
        ZomeCallResponse::NetworkError(err) => { // Network error, we could try again
          Err(wasm_error!(WasmErrorInner::Guest(format!("There was a network error: {:?}", err))))
        },
        ZomeCallResponse::CountersigningSession(err) => { 
          Err(wasm_error!(WasmErrorInner::Guest(format!("There was a network error: {:?}", err))))
        },
    }
}
/** Don't change */
#[cfg(feature = "exercise")]
extern crate private_publication_lobby;
