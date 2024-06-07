import { Buffer } from 'buffer';
import { CreatePowoOptions, EthPowoMessage, VerifyPowoOptions } from './types';
import { authWithII } from './auth';
const { validateDelegationAndGetPrincipal } = require('./icp-sig-verifier/sig_verifier_js');

export const create = async (
  { message }: CreatePowoOptions,
  url?: string
): Promise<string> => {
  const tokenDurationMs = 1000 * 5 * 60; // 5 minutes
  const expires = new Date(Date.now() + tokenDurationMs);
  const powoMessage: EthPowoMessage = {
    expires: expires.toISOString(),
    ...(message ? { message } : {}),
  };
  const powoString = JSON.stringify(powoMessage);
  const powoBuffer = Buffer.from(powoString);

  const delegationIdentity = await authWithII({
    // The url needs to be aligned with the root key in the backend
    // url: "http://internet_identity.localhost:5173",
    url: url || "https://jqajs-xiaaa-aaaad-aab5q-cai.ic0.app/",
    sessionPublicKey: new Uint8Array(powoBuffer),
  }) as any;

  // authnMethod "passkey"
  // delegations [{…}]
  // userPublicKey Uint8Array(62)

  // make the delegation stringifyable
  let delegation = delegationIdentity.delegations[0];
  delegation.delegation.expiration = delegation.delegation.expiration.toString();
  const delegationString = JSON.stringify(delegation);
  const delegationBuffer = Buffer.from(delegationString);

  const powoB64 = powoBuffer.toString('base64');
  const delegationB64 = delegationBuffer.toString('base64');
  return `${powoB64}.${delegationB64}`;
};

export const verify = async (
  address: string,
  proof: string,
  { message }: VerifyPowoOptions,
  currentTimeNsOverride?: bigint,
  iiCanisterIdOverride?: string,
): Promise<boolean> => {
  console.log('verifyPowo raw', { address, proof });
  const [b64Message, b64Delegation] = proof.split('.');
  const decodedDelegation = Buffer.from(b64Delegation, 'base64').toString();
  const decodedMessageAsBuffer = Buffer.from(b64Message, 'base64');
  console.log(b64Message, decodedMessageAsBuffer.toString());
  const decodedMessage = JSON.parse(decodedMessageAsBuffer.toString()) as EthPowoMessage;

  console.log('verifyPowo decoded', { decodedSignature: decodedDelegation, decodedMessage });

  // Prepare the parameters
  const challenge: Uint8Array = decodedMessageAsBuffer;
  const signedDelegationChainJson: string = decodedDelegation;
  const currentTimeNs: bigint = currentTimeNsOverride ? currentTimeNsOverride : BigInt(1000*Date.now());
  const iiCanisterId: string =  iiCanisterIdOverride ? iiCanisterIdOverride : "rdmx6-jaaaa-aaaaa-aaadq-cai";
  const icRootPublicKeyRaw: Uint8Array = iiCanisterIdOverride ? new Uint8Array([48, 129, 130, 48, 29, 6, 13, 43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 1, 2, 1, 6, 12, 43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 2, 1, 3, 97, 0, 160, 77, 135, 31, 145, 159, 194, 80, 174, 43, 90, 124, 144, 184, 158, 59, 46, 84, 63, 77, 205, 139, 206, 236, 45, 175, 165, 202, 64, 205, 204, 110, 134, 175, 248, 58, 17, 63, 123, 30, 113, 149, 87, 103, 105, 233, 207, 182, 10, 149, 70, 250, 9, 129, 114, 188, 216, 126, 102, 164, 188, 37, 26, 255, 23, 85, 220, 156, 57, 132, 182, 230, 251, 237, 219, 13, 145, 130, 112, 217, 116, 199, 188, 88, 169, 91, 105, 27, 42, 166, 181, 5, 135, 212, 212, 118]) : new Uint8Array([48, 129, 130, 48, 29, 6, 13, 43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 1, 2, 1, 6, 12, 43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 2, 1, 3, 97, 0, 160, 77, 135, 31, 145, 159, 194, 80, 174, 43, 90, 124, 144, 184, 158, 59, 46, 84, 63, 77, 205, 139, 206, 236, 45, 175, 165, 202, 64, 205, 204, 110, 134, 175, 248, 58, 17, 63, 123, 30, 113, 149, 87, 103, 105, 233, 207, 182, 10, 149, 70, 250, 9, 129, 114, 188, 216, 126, 102, 164, 188, 37, 26, 255, 23, 85, 220, 156, 57, 132, 182, 230, 251, 237, 219, 13, 145, 130, 112, 217, 116, 199, 188, 88, 169, 91, 105, 27, 42, 166, 181, 5, 135, 212, 212, 118]); // FIXME replace latter with real II mainnet key
  // Verify the POWO and delegation by calling into icp-sig-verifier
  try {
    const principal = validateDelegationAndGetPrincipal(challenge, signedDelegationChainJson, currentTimeNs, iiCanisterId, icRootPublicKeyRaw);
    console.log('Delegation verified, principal:', principal);
  } catch (error) {
    throw new Error('Verification failed');
  }

  if (new Date(decodedMessage.expires).getTime() < Date.now()) {
    throw new Error('Token Expired');
  }

  if (decodedMessage.message && message && decodedMessage.message !== message) {
    throw new Error('Bad message');
  }

  return true;
};
