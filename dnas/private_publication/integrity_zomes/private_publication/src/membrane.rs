use std::sync::Arc;

use hdi::prelude::*;
use membrane_proof::PrivatePublicationMembraneProof;

use crate::properties::progenitor;

pub fn is_membrane_proof_valid(
    for_agent: AgentPubKey,
    membrane_proof: Option<MembraneProof>,
) -> ExternResult<ValidateCallbackResult> {
    let progenitor = progenitor()?;

    if for_agent == progenitor {
        Ok(ValidateCallbackResult::Valid)
    } else {
        match membrane_proof {
            Some(membrane_proof_bytes) => {
                // let record: Record = membrane_proof_bytes.try_into()?;
                // let record: Record = Record::try_from(membrane_proof_bytes.into_raw())?;
                let record =
                    Record::try_from(Arc::try_unwrap(membrane_proof_bytes).map_err(|_e| {
                        wasm_error!(WasmErrorInner::Guest(String::from(
                            "error converting membrane proof bytes"
                        )))
                    })?)
                    .map_err(|_e| {
                        wasm_error!(WasmErrorInner::Guest(String::from(
                            "serialize membrane proof error"
                        )))
                    })?;
                if progenitor == record.action().author().clone() {
                    if verify_signature(
                        progenitor,
                        record.signature().clone(),
                        record.clone().action_hashed().content.clone(),
                    )? {
                        let private_pub_membrane_proof: PrivatePublicationMembraneProof = record
                            .entry
                            .to_app_option()
                            .map_err(|e| wasm_error!(WasmErrorInner::Guest(e.into())))?
                            .ok_or(wasm_error!(WasmErrorInner::Guest(String::from(
                                "invalid entry type"
                            ))))?;
                        if private_pub_membrane_proof.dna_hash == dna_info()?.hash {
                            if private_pub_membrane_proof.recipient == for_agent {
                                Ok(ValidateCallbackResult::Valid)
                            } else {
                                Ok(ValidateCallbackResult::Invalid(String::from(
                                    "mismatching agent key",
                                )))
                            }
                        } else {
                            Ok(ValidateCallbackResult::Invalid(String::from(
                                "invalid dna hash in membrane proof",
                            )))
                        }
                    } else {
                        Ok(ValidateCallbackResult::Invalid(String::from(
                            "membrane proof has invalid signature",
                        )))
                    }
                } else {
                    Ok(ValidateCallbackResult::Valid)
                }
            }
            None => Ok(ValidateCallbackResult::Invalid(String::from(
                "membrane proof not provided",
            ))),
        }
    }
}
