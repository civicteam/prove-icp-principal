import { Buffer } from 'buffer';
import { CreatePowoOptions, ICPPowoMessage, VerifyPowoOptions } from './types';
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

// ICP root key for mainnet 
const ROOT_PUBLIC_KEY_RAW_IC = new Uint8Array([
  0x81, 0x4c, 0x0e, 0x6e, 0xc7, 0x1f, 0xab, 0x58, 0x3b, 0x08, 0xbd, 0x81, 0x37, 0x3c, 0x25, 0x5c, 0x3c, 0x37, 0x1b,
  0x2e, 0x84, 0x86, 0x3c, 0x98, 0xa4, 0xf1, 0xe0, 0x8b, 0x74, 0x23, 0x5d, 0x14, 0xfb, 0x5d, 0x9c, 0x0c, 0xd5, 0x46,
  0xd9, 0x68, 0x5f, 0x91, 0x3a, 0x0c, 0x0b, 0x2c, 0xc5, 0x34, 0x15, 0x83, 0xbf, 0x4b, 0x43, 0x92, 0xe4, 0x67, 0xdb,
  0x96, 0xd6, 0x5b, 0x9b, 0xb4, 0xcb, 0x71, 0x71, 0x12, 0xf8, 0x47, 0x2e, 0x0d, 0x5a, 0x4d, 0x14, 0x50, 0x5f, 0xfd,
  0x74, 0x84, 0xb0, 0x12, 0x91, 0x09, 0x1c, 0x5f, 0x87, 0xb9, 0x88, 0x83, 0x46, 0x3f, 0x98, 0x09, 0x1a, 0x0b, 0xaa,
  0xae,
]);

// Civic backend canister ID - currently testing with local 
const civicBackendCanisterId = process.env.VITE_CIVIC_BACKEND_CANISTER_ID;


export const uint8ArrayToHexString = (bytes: Uint8Array | number[]): string => {
  if (!(bytes instanceof Uint8Array)) {
    bytes = Uint8Array.from(bytes);
  }
  return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
};

export const create = async ({ message }: CreatePowoOptions, url?: string): Promise<string> => {
  const tokenDurationMs = 1000 * 5 * 60; // 5 minutes
  const expires = new Date(Date.now() + tokenDurationMs);
  const powoMessage: ICPPowoMessage = {
    expires: expires.toISOString(),
    ...(message ? { message } : {}),
  };
  const powoString = JSON.stringify(powoMessage);
  const powoBuffer = Buffer.from(powoString);

  const delegationIdentity = (await authWithII({
    // The url needs to be aligned with the root key in the backend
    url: url || 'https://identity.ic0.app',
    derivationOrigin: civicBackendCanisterId,
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
  iiCanisterIdOverride?: string,
  rootPublicKeyOverride?: Uint8Array
): Promise<boolean> => {
  console.log('verifyPowo raw', { address, proof });
  const [b64Message, b64Delegation] = proof.split('.');
  const decodedDelegation = Buffer.from(b64Delegation, 'base64').toString();
  const decodedMessageAsBuffer = Buffer.from(b64Message, 'base64');
  console.log(b64Message, decodedMessageAsBuffer.toString());
  const decodedMessage = JSON.parse(decodedMessageAsBuffer.toString()) as ICPPowoMessage;

  console.log('verifyPowo decoded', { decodedSignature: decodedDelegation, decodedMessage });

  // Prepare the parameters
  const challenge: Uint8Array = decodedMessageAsBuffer;
  const signedDelegationChainJson: string = decodedDelegation;
  const currentTimeNs: bigint = currentTimeNsOverride ? currentTimeNsOverride : process.hrtime.bigint();
  const iiCanisterId: string = iiCanisterIdOverride ? iiCanisterIdOverride : 'rdmx6-jaaaa-aaaaa-aaadq-cai';
  const icRootPublicKeyRaw: Uint8Array = rootPublicKeyOverride ? rootPublicKeyOverride : ROOT_PUBLIC_KEY_RAW_IC;
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
    if (address !== principal) {
      throw new Error('Invalid principal');
    }
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
