import { validateDelegationAndGetPrincipal } from './icp-sig-verifier/sig_verifier_js';
// import { TypedDataDomain, TypedDataField } from '@ethersproject/abstract-signer';
import { Buffer } from 'buffer';
import { verifyTypedData } from 'ethers/lib/utils';
import { CreatePowoOptions, defaultDomain, EthPowoMessage, VerifyPowoOptions } from './types';
import { authWithII } from './auth';

const getTypes = (verifierAddress?: string, message?: string) => {
  const useTypes = {
    PoWo: [{ name: 'expires', type: 'string' }],
  };
  if (verifierAddress) {
    useTypes.PoWo.push({ name: 'verifierAddress', type: 'string' });
  }
  if (message) {
    useTypes.PoWo.push({ name: 'message', type: 'string' });
  }
  return useTypes;
};

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
  const msgString = JSON.stringify(powoMessage);
  const messageB64 = Buffer.from(msgString, 'base64');

  const delegationIdentity = await authWithII({
    // The url needs to be aligned with the root key in the backend
    // url: "http://internet_identity.localhost:5173",
    url: url || "https://jqajs-xiaaa-aaaad-aab5q-cai.ic0.app/",
    sessionPublicKey: new Uint8Array(messageB64),
  });
  const delegationString = JSON.stringify(delegationIdentity.getDelegation().toJSON());

  const delegationB64 = Buffer.from(delegationString).toString('base64');
  return `${messageB64}.${delegationB64}`;
};

export const verify = async (
  address: string,
  proof: string,
  { message }: VerifyPowoOptions
): Promise<boolean> => {
  console.log('verifyPowo raw', { address, proof });
  const [b64TypedMessage, delegation] = proof.split('.');
  const decodedDelegation = Buffer.from(delegation, 'base64').toString();
  const decodedMessageAsBuffer = Buffer.from(b64TypedMessage, 'base64');
  const decodedMessage = JSON.parse(decodedMessageAsBuffer.toString('utf-8')) as EthPowoMessage;

  console.log('verifyPowo decoded', { decodedSignature: decodedDelegation, decodedMessage });

  // Prepare the parameters
  const challenge: Uint8Array = decodedMessageAsBuffer;
  const signedDelegationChainJson: string = decodedDelegation;
  const currentTimeNs: bigint = BigInt(1000*Date.now());
  const iiCanisterId: string = "be2us-64aaa-aaaaa-qaabq-cai";
  //  "rdmx6-jaaaa-aaaaa-aaadq-cai"; // Internet Identity Canister ID
  const icRootPublicKeyRaw: Uint8Array = new Uint8Array([48, 129, 130, 48, 29, 6, 13, 43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 1, 2, 1, 6, 12, 43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 2, 1, 3, 97, 0, 160, 77, 135, 31, 145, 159, 194, 80, 174, 43, 90, 124, 144, 184, 158, 59, 46, 84, 63, 77, 205, 139, 206, 236, 45, 175, 165, 202, 64, 205, 204, 110, 134, 175, 248, 58, 17, 63, 123, 30, 113, 149, 87, 103, 105, 233, 207, 182, 10, 149, 70, 250, 9, 129, 114, 188, 216, 126, 102, 164, 188, 37, 26, 255, 23, 85, 220, 156, 57, 132, 182, 230, 251, 237, 219, 13, 145, 130, 112, 217, 116, 199, 188, 88, 169, 91, 105, 27, 42, 166, 181, 5, 135, 212, 212, 118]);
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
