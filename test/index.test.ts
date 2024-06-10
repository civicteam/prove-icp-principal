import { TextEncoder, TextDecoder } from 'util';
Object.assign(global, { TextDecoder, TextEncoder });

import { verify } from '../src';

async function loadSigVerifier() {
  if (typeof require !== 'undefined' && typeof exports !== 'undefined') {
    // CommonJS environment (Node.js)
    return require('../src/icp-sig-verifier.nodejs/sig_verifier_js');
  } else {
    // ESM environment (Browser)
    return import('../src/icp-sig-verifier/sig_verifier_js');
  }
}

const messageFixture = {
  nonce: '0428e3865755606a95be4ce1bb9886ea67377258dc210a28132c51c38f5af949',
  timestamp: 1717759372,
};
const proofJWTFixture =
  'eyJleHBpcmVzIjoiMjAyNC0wNi0wN1QxNzoxMDoxMS4wNjNaIiwibWVzc2FnZSI6IntcIm5vbmNlXCI6XCIxMGU1ODE1OGE5ODRmMWMyNjEzMTBmZDExMjJlNGNkOGYxZWIxYzQzOGQxY2IzYjBiNDIzZTVlMDViNDA4YmVmXCIsXCJ0aW1lc3RhbXBcIjoxNzE3Nzc5OTExfSJ9.eyJkZWxlZ2F0aW9ucyI6W3siZGVsZWdhdGlvbiI6eyJwdWJrZXkiOiI3YjIyNjU3ODcwNjk3MjY1NzMyMjNhMjIzMjMwMzIzNDJkMzAzNjJkMzAzNzU0MzEzNzNhMzEzMDNhMzEzMTJlMzAzNjMzNWEyMjJjMjI2ZDY1NzM3MzYxNjc2NTIyM2EyMjdiNWMyMjZlNmY2ZTYzNjU1YzIyM2E1YzIyMzEzMDY1MzUzODMxMzUzODYxMzkzODM0NjYzMTYzMzIzNjMxMzMzMTMwNjY2NDMxMzEzMjMyNjUzNDYzNjQzODY2MzE2NTYyMzE2MzM0MzMzODY0MzE2MzYyMzM2MjMwNjIzNDMyMzM2NTM1NjUzMDM1NjIzNDMwMzg2MjY1NjY1YzIyMmM1YzIyNzQ2OTZkNjU3Mzc0NjE2ZDcwNWMyMjNhMzEzNzMxMzczNzM3MzkzOTMxMzE3ZDIyN2QiLCJleHBpcmF0aW9uIjoiMTdkNmM5NWYxZjI0OWZlYSJ9LCJzaWduYXR1cmUiOiJkOWQ5ZjdhMjZiNjM2NTcyNzQ2OTY2Njk2MzYxNzQ2NTU5MDFmZGQ5ZDlmN2EyNjQ3NDcyNjU2NTgzMDE4MzAxODMwMTgyMDQ1ODIwMjY3ZDEwOGI4MjUxNDljODg5MjI3ZjIyMGNhMjAxMTM4Y2U2MjFjMzFjN2MzY2YxNzQxMTdlNzAxNTExMGJiNzgzMDI0ODYzNjE2ZTY5NzM3NDY1NzI4MzAxODIwNDU4MjAyOTgyOTRjZWQwMjVlZDljMzYxMmY1MDhmOTliMGFkOTRmYjkxMjljZjdiMzIxODgzZmNkNGFkODk3YTk4NjVmODMwMTgyMDQ1ODIwMzg1ZjQ4NmNiZWZmYzlmZGEzYjU3MTJjY2RjZjllNzgwNzE5NGYwMTI4OWQ2YjMxNTRkNzg3OGRiMDI1YzQwODgzMDE4MzAxODIwNDU4MjA0MTg4MmJjMGM2NGY1Y2ViZGNlYzYxZDZkZDU0YjBjODY5ZmZkOWQyMzJkOThkNDhmYjFiM2E0OGY5NGRlZDgyODMwMjRhODAwMDAwMDAwMDEwMDAwZDAxMDE4MzAxODMwMTgzMDI0ZTYzNjU3Mjc0Njk2NjY5NjU2NDVmNjQ2MTc0NjE4MjAzNTgyMDY0MzYzOGIyMDlkZmJmY2ZkNzc5NjMxOGUzMmM3YmIzNGM1ZGViODQyYmNjMDU2NjI4ODliNDUzZWQ4OTYzOWQ4MjA0NTgyMGFjNWY4YjI4Y2NkMzMwMzBiYWFlN2E2ZWJlY2UwYjk2NWIxMzQ1MDYyNmY0OWMzNWRkZDRhYjY2NGRjN2NiMzc4MjA0NTgyMDA2ZjY2OTc2N2YxM2U2YzI5ZjJkNTM4ZjdjNmM2YjlmNDE1NDBmY2YyYWY2ZDI0Njc3Yjk2NDE2YTExYzhlOTU4MjA0NTgyMGQxZTZlMzUxNzI5ZWU0Yjc2NzhkOGRjYzE4MDU2MDIzNTdiNjE0ZGZiNWU1ZThmYTdiYmZmNWM5Y2NmOTY4MjA4MjA0NTgyMDlkYzZjMDQ0NjY2YTYxNTFlNDZhNTY2YWMyNzIzNWJjODVhMTNiMTI4YzQ0N2U3OTJkOGFiODg2YTkwM2E4ODQ4MzAxODIwNDU4MjA4Y2FhYzQwMDA4MDZlMDdmMTg1OTE4OTRjMWY2ZDMxZTA3YTZlYzQ4ZDY5ZWEzYWJiMDJiZjg0OGIwZTc0M2MyODMwMjQ0NzQ2OTZkNjU4MjAzNDljN2U0ODliM2M1ZjdiMWViMTc2OTczNjk2NzZlNjE3NDc1NzI2NTU4MzA4MjllNGJiOGUzMjZhZjE1NTVkNjdiN2VhMjU2YzMyZDdiZmY0MGZmNjk2ZTFhMzY5YmRjNzMwZDRiOTIyYWFmNzJmZDBlMTJjYTE4YjRlODM3YjgxNDZhMmRlNDJlYzQ2NDc0NzI2NTY1ODMwMTgyMDQ1ODIwOWE5OTY0Y2VlNDY0ODMxNjYwMTZlYjZiOWQ0NjZkMWE3MDExODNlZjlhYWYwMTY3ODVmODc3NzZlNzQ0OTM0ZjgzMDI0MzczNjk2NzgzMDI1ODIwOWJlM2NiMmNmMGFjMGRiMDY3ZDcyYTM1MjM5ZjYwOTJkMjkyZjFmNmI4ODcyM2RjNGRkZmJlNTkwYWQ5OWIzYjgzMDE4MzAyNTgyMDVmZjVjZmM5OGM4OTlmMzJkMTkzMDI5Mjc0OTc1MWJjYmMyNmVjZjc4N2NlZmI0ZDc2ZGY3NDhmOTcwMzk1Yjc4MjAzNDA4MjA0NTgyMDgxNTczMjNmNjc5NDA0YzQ4MWRkYzc3MzkxZDVkYzU0MjRmM2Y1MDJkZjg3MDk1YWNjNWE5NWE1N2M5NzdhOWIifV0sInB1YmxpY0tleSI6IjMwM2MzMDBjMDYwYTJiMDYwMTA0MDE4M2I4NDMwMTAyMDMyYzAwMGE4MDAwMDAwMDAwMTAwMDBkMDEwMTYyODY4YTcwMWJlNzFhYzE5OWFjNmRhODE3MWYwZTQyZjM0YTU5ZGUyN2IyM2ZjYmEzMDBmMDdmZDJlMzZjMmMifQ==';
const currentTimeNsOverride = BigInt(0);
const iiCanisterIdOverride = 'aovwi-4maaa-aaaaa-qaagq-cai';

const expired = {
  address: '0x33A17d5f19827EB220a3C05e33E5678A8b7b45Eb',
  proof:
    'eyJleHBpcmVzIjoiMjAyMy0wNS0wNFQxMzoyODoxNy45MThaIiwibWVzc2FnZSI6InRlc3QifQ==.MHhiMmEyZmQ5MWFiMDNkYzQwN2UwMjIxZDdhMjVlOGY5ZDIzNmI5Y2U1NGYxODA1MDVjYjE2NWYwMmMyMDQxMTBkNzhkNDRhMTQzMWY4NTI3YWY2OGZjZTg1MWRjZmI2ZDcwYzA5NjVmN2FlNGM2NWYyYjcwZDRkOWU4MjBlOWRiOTFj',
};

describe('prove-icp-principal', () => {
  afterEach(() => jest.restoreAllMocks());

  let message: string;
  beforeEach(() => {
    message = JSON.stringify(messageFixture);
  });

  it('creates a wallet ownership proof when a signer function is provided', async () => {
    // const proof = await create({
    //   message,
    // });
    // expect(proof).toMatch(/.*\..*/); // the message is a base64 version of the signature concatenated with the message
  });

  describe('validateDelegationAndGetPrincipal', () => {
    it('should return a principal when validation is successful', async () => {
      // The challenge should be the same as the pubkey in the delegation
      const challengeHex = '302a300506032b6570032100eb217306a19b5eda6a2a7e0679b9003759c511a0e05df393829e6fa52766ad8e';
      const challenge = Uint8Array.from(Buffer.from(challengeHex, 'hex'));

      const publicKeyHex = challengeHex; // The same as the challenge for this test
      const signatureHex =
        '85f0ac9af8109ceed6a8be80a699d24a6fa36b017b7dbc72d160c5550d0d040ae200dcd0e775a8c0f4e41f41a32c921185979be1e33b41b5a22c1d693edf2902';
      const expirationHex = '17b5b384762bfd21';

      // Ensure the publicKey and delegation.pubkey are properly encoded
      const signedDelegationChainJson = JSON.stringify({
        delegations: [
          {
            delegation: {
              pubkey: Buffer.from(publicKeyHex, 'hex').toString('hex'), // Encode to hex
              expiration: expirationHex,
            },
            signature: Buffer.from(signatureHex, 'hex').toString('hex'), // Encode to hex
          },
        ],
        publicKey: Buffer.from(publicKeyHex, 'hex').toString('hex'), // Encode to hex
      });

      const currentTimeNs = BigInt(Date.now() * 1_000_000); // Current time in nanoseconds
      const iiCanisterId = 'jqajs-xiaaa-aaaad-aab5q-cai'; // Replace with a valid II canister ID
      const icRootPublicKeyRaw = new Uint8Array([
        0x81, 0x4c, 0x0e, 0x6e, 0xc7, 0x1f, 0xab, 0x58, 0x3b, 0x08, 0xbd, 0x81, 0x37, 0x3c, 0x25, 0x5c, 0x3c, 0x37,
        0x1b, 0x2e, 0x84, 0x86, 0x3c, 0x98, 0xa4, 0xf1, 0xe0, 0x8b, 0x74, 0x23, 0x5d, 0x14, 0xfb, 0x5d, 0x9c, 0x0c,
        0xd5, 0x46, 0xd9, 0x68, 0x5f, 0x91, 0x3a, 0x0c, 0x0b, 0x2c, 0xc5, 0x34, 0x15, 0x83, 0xbf, 0x4b, 0x43, 0x92,
        0xe4, 0x67, 0xdb, 0x96, 0xd6, 0x5b, 0x9b, 0xb4, 0xcb, 0x71, 0x71, 0x12, 0xf8, 0x47, 0x2e, 0x0d, 0x5a, 0x4d,
        0x14, 0x50, 0x5f, 0xfd, 0x74, 0x84, 0xb0, 0x12, 0x91, 0x09, 0x1c, 0x5f, 0x87, 0xb9, 0x88, 0x83, 0x46, 0x3f,
        0x98, 0x09, 0x1a, 0x0b, 0xaa, 0xae,
      ]);

      try {
        const { validateDelegationAndGetPrincipal } = await loadSigVerifier();
        const principal = validateDelegationAndGetPrincipal(
          challenge,
          signedDelegationChainJson,
          currentTimeNs,
          iiCanisterId,
          icRootPublicKeyRaw
        );

        console.log('principal', principal);

        expect(principal).toBeDefined();
        // Add more assertions based on what the valid principal should be
      } catch (error) {
        console.log(error);
        throw new Error('Verification failed');
      }
    });
  });

  // it('verifies wallet ownership with provided signer function', async () => {
  //   const verifyData = {
  //     challenge: 'YSBjaGFsbGVuZ2UsIGkuZS4gYSBzdHJpbmcgb2YgYXQgbGVhc3QgMzIgYnl0ZXM=', // Base64 encoded challenge
  //     authMethod: 'someAuthMethod',
  //     delegationIdentity: {
  //       kind: 'someKind',
  //       delegations: [
  //         {
  //           delegation: {
  //             pubkey: 'publicKeyStringHere',
  //             expiration: '2024-12-31T23:59:59Z',
  //           },
  //           signature: 'signatureStringHere',
  //         },
  //       ],
  //       userPublicKey: 'userPublicKeyStringHere',
  //     },
  //   };
  //   const { validateDelegationAndGetPrincipal } = await loadSigVerifier();
  //   await expect(
  //     verify('undefined', proofJWTFixture, { message }, currentTimeNsOverride, iiCanisterIdOverride)
  //   ).resolves.not.toThrow();
  // });

  // it('throws an error if the transaction is signed with a different key', async () => {
  //   const someOtherKey = Wallet.createRandom();

  //   const proof = await create({
  //     message,
  //   });
  //   await expect(verify(someOtherKey.address, proof, { message })).rejects.toThrow();
  // });

  // it('throws an error if the proof is expired', async () => {
  //   await expect(verify(expired.address, expired.proof, { message: 'test' })).rejects.toThrow('Token Expired');
  // });

  // it("throws an error if the message doesn't match", async () => {
  //   const proof = await create({
  //     message: 'bad',
  //   });
  //   await expect(verify(wallet.address, proof, { message: 'test' })).rejects.toThrow('Bad message');
  // });
});
