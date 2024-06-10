/* tslint:disable */
/* eslint-disable */
/**
* Verifies a basic (i.e. not a canister signature) IC supported signature.
* Supported signature schemes: https://internetcomputer.org/docs/current/references/ic-interface-spec/#signatures
*
* Throws an error if the signature verification fails.
* @param {Uint8Array} msg
* @param {Uint8Array} signature
* @param {Uint8Array} public_key
*/
export function verifyBasicSignature(msg: Uint8Array, signature: Uint8Array, public_key: Uint8Array): void;
/**
* Verifies an IC canister signature.
* More details: https://internetcomputer.org/docs/current/references/ic-interface-spec/#canister-signatures
*
* Throws an error if the signature verification fails.
* @param {Uint8Array} message
* @param {Uint8Array} signature
* @param {Uint8Array} public_key
* @param {Uint8Array} ic_root_public_key
*/
export function verifyCanisterSignature(message: Uint8Array, signature: Uint8Array, public_key: Uint8Array, ic_root_public_key: Uint8Array): void;
/**
* Verifies any IC supported signature.
* Supported signature schemes: https://internetcomputer.org/docs/current/references/ic-interface-spec/#signatures
*
* Throws an error if the signature verification fails.
* @param {Uint8Array} message
* @param {Uint8Array} signature
* @param {Uint8Array} public_key
* @param {Uint8Array} ic_root_public_key
*/
export function verifyIcSignature(message: Uint8Array, signature: Uint8Array, public_key: Uint8Array, ic_root_public_key: Uint8Array): void;
/**
* Verifies the validity of the given signed delegation chain wrt. the challenge, and the other parameters.
* Specifically:
*  * `signed_delegation_chain` contains exactly one delegation, denoted below as `delegations[0]`
*  * `delegations[0].pubkey` equals `challenge` (i.e. challenge is the "session key")
*  * `signed_delegation_chain.publicKey` is a public key for canister signatures of `ii_canister_id`
*  * `current_time_ns` denotes point in time before `delegations[0].expiration`
*  *  TODO: `current_time_ns` denotes point in time that is not more than 5min after signature creation time
*     (as specified in the certified tree of the Certificate embedded in the signature)
*  * `delegations[0].signature` is a valid canister signature on a representation-independent hash of `delegations[0]`,
*    wrt. `signed_delegation_chain.publicKey` and `ic_root_public_key_raw`
*
* On success returns textual representation of the self-authenticating Principal determined by
* public key `signed_delegation_chain.publicKey` (which identifies the user).
* @param {Uint8Array} challenge
* @param {string} signed_delegation_chain_json
* @param {bigint} current_time_ns
* @param {string} ii_canister_id
* @param {Uint8Array} ic_root_public_key_raw
* @returns {string}
*/
export function validateDelegationAndGetPrincipal(challenge: Uint8Array, signed_delegation_chain_json: string, current_time_ns: bigint, ii_canister_id: string, ic_root_public_key_raw: Uint8Array): string;
