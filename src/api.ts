import { Buffer } from 'buffer';
import { CreatePowoOptions, EthPowoMessage, VerifyPowoOptions } from './types';
import { authWithII } from './auth';

async function loadSigVerifier() {
  if (typeof require !== 'undefined' && typeof exports !== 'undefined') {
    // CommonJS environment (Node.js)
    return require('./icp-sig-verifier.nodejs/sig_verifier_js');
  } else {
    // ESM environment (Browser)
    return import('./icp-sig-verifier/sig_verifier_js');
  }
}

const ROOT_PUBLIC_KEY_RAW_LOCAL = new Uint8Array([
  0x81, 0x4c, 0x0e, 0x6e, 0xc7, 0x1f, 0xab, 0x58, 0x3b, 0x08, 0xbd, 0x81, 0x37, 0x3c, 0x25, 0x5c, 0x3c, 0x37, 0x1b,
  0x2e, 0x84, 0x86, 0x3c, 0x98, 0xa4, 0xf1, 0xe0, 0x8b, 0x74, 0x23, 0x5d, 0x14, 0xfb, 0x5d, 0x9c, 0x0c, 0xd5, 0x46,
  0xd9, 0x68, 0x5f, 0x91, 0x3a, 0x0c, 0x0b, 0x2c, 0xc5, 0x34, 0x15, 0x83, 0xbf, 0x4b, 0x43, 0x92, 0xe4, 0x67, 0xdb,
  0x96, 0xd6, 0x5b, 0x9b, 0xb4, 0xcb, 0x71, 0x71, 0x12, 0xf8, 0x47, 0x2e, 0x0d, 0x5a, 0x4d, 0x14, 0x50, 0x5f, 0xfd,
  0x74, 0x84, 0xb0, 0x12, 0x91, 0x09, 0x1c, 0x5f, 0x87, 0xb9, 0x88, 0x83, 0x46, 0x3f, 0x98, 0x09, 0x1a, 0x0b, 0xaa,
  0xae,
]);

export const uint8ArrayToHexString = (bytes: Uint8Array | number[]): string => {
  if (!(bytes instanceof Uint8Array)) {
    bytes = Uint8Array.from(bytes);
  }
  return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
};

export const create = async ({ message }: CreatePowoOptions, url?: string): Promise<string> => {
  const tokenDurationMs = 1000 * 5 * 60; // 5 minutes
  const expires = new Date(Date.now() + tokenDurationMs);
  const powoMessage: EthPowoMessage = {
    expires: expires.toISOString(),
    ...(message ? { message } : {}),
  };
  const powoString = JSON.stringify(powoMessage);
  const powoBuffer = Buffer.from(powoString);

  const delegationIdentity = (await authWithII({
    // The url needs to be aligned with the root key in the backend
    // url: "http://internet_identity.localhost:5173",
    url: url || 'https://jqajs-xiaaa-aaaad-aab5q-cai.ic0.app/',
    sessionPublicKey: new Uint8Array(powoBuffer),
  })) as any;

  // stringify the delegation
  const delegationChain = {
    delegations: delegationIdentity.delegations,
    publicKey: delegationIdentity.userPublicKey,
  };
  const delegationString = JSON.stringify(delegationChain, (_, v) => {
    if (typeof v === 'bigint') {
      // We need to expiration date to be hex string.
      return v.toString(16);
    }
    if (v instanceof Uint8Array) {
      // We need the keys to be hex strings.
      return uint8ArrayToHexString(v);
    }
    return v;
  });
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
  iiCanisterIdOverride?: string
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
  const currentTimeNs: bigint = currentTimeNsOverride ? currentTimeNsOverride : process.hrtime.bigint();
  const iiCanisterId: string = iiCanisterIdOverride ? iiCanisterIdOverride : 'rdmx6-jaaaa-aaaaa-aaadq-cai';
  const icRootPublicKeyRaw: Uint8Array = iiCanisterIdOverride
    ? ROOT_PUBLIC_KEY_RAW_LOCAL
    : new Uint8Array([
        48, 129, 130, 48, 29, 6, 13, 43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 1, 2, 1, 6, 12, 43, 6, 1, 4, 1, 130, 220, 124,
        5, 3, 2, 1, 3, 97, 0, 160, 77, 135, 31, 145, 159, 194, 80, 174, 43, 90, 124, 144, 184, 158, 59, 46, 84, 63, 77,
        205, 139, 206, 236, 45, 175, 165, 202, 64, 205, 204, 110, 134, 175, 248, 58, 17, 63, 123, 30, 113, 149, 87, 103,
        105, 233, 207, 182, 10, 149, 70, 250, 9, 129, 114, 188, 216, 126, 102, 164, 188, 37, 26, 255, 23, 85, 220, 156,
        57, 132, 182, 230, 251, 237, 219, 13, 145, 130, 112, 217, 116, 199, 188, 88, 169, 91, 105, 27, 42, 166, 181, 5,
        135, 212, 212, 118,
      ]); // FIXME replace latter with real II mainnet key
  // Verify the POWO and delegation by calling into icp-sig-verifier
  try {
    console.log(signedDelegationChainJson);
    const { validateDelegationAndGetPrincipal } = await loadSigVerifier();
    const principal = validateDelegationAndGetPrincipal(
      challenge,
      signedDelegationChainJson,
      currentTimeNs,
      iiCanisterId,
      icRootPublicKeyRaw
    );
    console.log('Delegation verified, principal:', principal);
  } catch (error) {
    console.log(error);
    throw new Error('Verification failed');
  }
  if (!currentTimeNsOverride && new Date(decodedMessage.expires).getTime() < Date.now()) {
    throw new Error('Token Expired');
  }

  if (decodedMessage.message && message && decodedMessage.message !== message) {
    throw new Error('Bad message');
  }

  return true;
};
