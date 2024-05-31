import { TypedDataDomain, TypedDataField } from '@ethersproject/abstract-signer';
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
  { domain = defaultDomain, message, verifierAddress }: CreatePowoOptions,
  url?: string
): Promise<string> => {
  const tokenDurationMs = 1000 * 5 * 60; // 5 minutes
  const expires = new Date(Date.now() + tokenDurationMs);
  const powoMessage: EthPowoMessage = {
    expires: expires.toISOString(),
    ...(message ? { message } : {}),
    ...(verifierAddress ? { verifierAddress } : {}),
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
  { domain = defaultDomain, message, verifierAddress }: VerifyPowoOptions
): Promise<boolean> => {
  console.log('verifyPowo raw', { address, proof });
  const [b64TypedMessage, signature] = proof.split('.');
  const decodedSignature = Buffer.from(signature, 'base64').toString();
  const decodedMessage = JSON.parse(Buffer.from(b64TypedMessage, 'base64').toString('utf-8')) as EthPowoMessage;

  console.log('verifyPowo decoded', { decodedSignature, decodedMessage });
  const useTypes = getTypes(verifierAddress, message);

  // TODO @lilly verify the delegation
  // https://github.com/dfinity/internet-identity/blob/5b9ed988a76322a5a87dd1f5f62f2029272f1c9c/src/sig-verifier-js/src/lib.rs#L89

  // const recoveredAddress = verifyTypedData(domain, useTypes, decodedMessage, decodedSignature);
  // if (recoveredAddress !== address) {
  //   throw new Error('Message was signed by unexpected wallet');
  // }

  if (new Date(decodedMessage.expires).getTime() < Date.now()) {
    throw new Error('Token Expired');
  }

  if (decodedMessage.message && message && decodedMessage.message !== message) {
    throw new Error('Bad message');
  }

  if (decodedMessage.verifierAddress && verifierAddress && decodedMessage.verifierAddress !== verifierAddress) {
    throw new Error('Bad verifier address');
  }
  return true;
};
