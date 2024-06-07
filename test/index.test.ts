import { TextEncoder, TextDecoder } from 'util';
Object.assign(global, { TextDecoder, TextEncoder });

import { verify } from '../src';

const messageFixture = {
  "nonce": "0428e3865755606a95be4ce1bb9886ea67377258dc210a28132c51c38f5af949",
  "timestamp": 1717759372
};
const proofJWTFixture = 'eyJleHBpcmVzIjoiMjAyNC0wNi0wN1QxNzoxMDoxMS4wNjNaIiwibWVzc2FnZSI6IntcIm5vbmNlXCI6XCIxMGU1ODE1OGE5ODRmMWMyNjEzMTBmZDExMjJlNGNkOGYxZWIxYzQzOGQxY2IzYjBiNDIzZTVlMDViNDA4YmVmXCIsXCJ0aW1lc3RhbXBcIjoxNzE3Nzc5OTExfSJ9.eyJkZWxlZ2F0aW9ucyI6W3siZGVsZWdhdGlvbiI6eyJwdWJrZXkiOiI3YjIyNjU3ODcwNjk3MjY1NzMyMjNhMjIzMjMwMzIzNDJkMzAzNjJkMzAzNzU0MzEzNzNhMzEzMDNhMzEzMTJlMzAzNjMzNWEyMjJjMjI2ZDY1NzM3MzYxNjc2NTIyM2EyMjdiNWMyMjZlNmY2ZTYzNjU1YzIyM2E1YzIyMzEzMDY1MzUzODMxMzUzODYxMzkzODM0NjYzMTYzMzIzNjMxMzMzMTMwNjY2NDMxMzEzMjMyNjUzNDYzNjQzODY2MzE2NTYyMzE2MzM0MzMzODY0MzE2MzYyMzM2MjMwNjIzNDMyMzM2NTM1NjUzMDM1NjIzNDMwMzg2MjY1NjY1YzIyMmM1YzIyNzQ2OTZkNjU3Mzc0NjE2ZDcwNWMyMjNhMzEzNzMxMzczNzM3MzkzOTMxMzE3ZDIyN2QiLCJleHBpcmF0aW9uIjoiMTdkNmM5NWYxZjI0OWZlYSJ9LCJzaWduYXR1cmUiOiJkOWQ5ZjdhMjZiNjM2NTcyNzQ2OTY2Njk2MzYxNzQ2NTU5MDFmZGQ5ZDlmN2EyNjQ3NDcyNjU2NTgzMDE4MzAxODMwMTgyMDQ1ODIwMjY3ZDEwOGI4MjUxNDljODg5MjI3ZjIyMGNhMjAxMTM4Y2U2MjFjMzFjN2MzY2YxNzQxMTdlNzAxNTExMGJiNzgzMDI0ODYzNjE2ZTY5NzM3NDY1NzI4MzAxODIwNDU4MjAyOTgyOTRjZWQwMjVlZDljMzYxMmY1MDhmOTliMGFkOTRmYjkxMjljZjdiMzIxODgzZmNkNGFkODk3YTk4NjVmODMwMTgyMDQ1ODIwMzg1ZjQ4NmNiZWZmYzlmZGEzYjU3MTJjY2RjZjllNzgwNzE5NGYwMTI4OWQ2YjMxNTRkNzg3OGRiMDI1YzQwODgzMDE4MzAxODIwNDU4MjA0MTg4MmJjMGM2NGY1Y2ViZGNlYzYxZDZkZDU0YjBjODY5ZmZkOWQyMzJkOThkNDhmYjFiM2E0OGY5NGRlZDgyODMwMjRhODAwMDAwMDAwMDEwMDAwZDAxMDE4MzAxODMwMTgzMDI0ZTYzNjU3Mjc0Njk2NjY5NjU2NDVmNjQ2MTc0NjE4MjAzNTgyMDY0MzYzOGIyMDlkZmJmY2ZkNzc5NjMxOGUzMmM3YmIzNGM1ZGViODQyYmNjMDU2NjI4ODliNDUzZWQ4OTYzOWQ4MjA0NTgyMGFjNWY4YjI4Y2NkMzMwMzBiYWFlN2E2ZWJlY2UwYjk2NWIxMzQ1MDYyNmY0OWMzNWRkZDRhYjY2NGRjN2NiMzc4MjA0NTgyMDA2ZjY2OTc2N2YxM2U2YzI5ZjJkNTM4ZjdjNmM2YjlmNDE1NDBmY2YyYWY2ZDI0Njc3Yjk2NDE2YTExYzhlOTU4MjA0NTgyMGQxZTZlMzUxNzI5ZWU0Yjc2NzhkOGRjYzE4MDU2MDIzNTdiNjE0ZGZiNWU1ZThmYTdiYmZmNWM5Y2NmOTY4MjA4MjA0NTgyMDlkYzZjMDQ0NjY2YTYxNTFlNDZhNTY2YWMyNzIzNWJjODVhMTNiMTI4YzQ0N2U3OTJkOGFiODg2YTkwM2E4ODQ4MzAxODIwNDU4MjA4Y2FhYzQwMDA4MDZlMDdmMTg1OTE4OTRjMWY2ZDMxZTA3YTZlYzQ4ZDY5ZWEzYWJiMDJiZjg0OGIwZTc0M2MyODMwMjQ0NzQ2OTZkNjU4MjAzNDljN2U0ODliM2M1ZjdiMWViMTc2OTczNjk2NzZlNjE3NDc1NzI2NTU4MzA4MjllNGJiOGUzMjZhZjE1NTVkNjdiN2VhMjU2YzMyZDdiZmY0MGZmNjk2ZTFhMzY5YmRjNzMwZDRiOTIyYWFmNzJmZDBlMTJjYTE4YjRlODM3YjgxNDZhMmRlNDJlYzQ2NDc0NzI2NTY1ODMwMTgyMDQ1ODIwOWE5OTY0Y2VlNDY0ODMxNjYwMTZlYjZiOWQ0NjZkMWE3MDExODNlZjlhYWYwMTY3ODVmODc3NzZlNzQ0OTM0ZjgzMDI0MzczNjk2NzgzMDI1ODIwOWJlM2NiMmNmMGFjMGRiMDY3ZDcyYTM1MjM5ZjYwOTJkMjkyZjFmNmI4ODcyM2RjNGRkZmJlNTkwYWQ5OWIzYjgzMDE4MzAyNTgyMDVmZjVjZmM5OGM4OTlmMzJkMTkzMDI5Mjc0OTc1MWJjYmMyNmVjZjc4N2NlZmI0ZDc2ZGY3NDhmOTcwMzk1Yjc4MjAzNDA4MjA0NTgyMDgxNTczMjNmNjc5NDA0YzQ4MWRkYzc3MzkxZDVkYzU0MjRmM2Y1MDJkZjg3MDk1YWNjNWE5NWE1N2M5NzdhOWIifV0sInB1YmxpY0tleSI6IjMwM2MzMDBjMDYwYTJiMDYwMTA0MDE4M2I4NDMwMTAyMDMyYzAwMGE4MDAwMDAwMDAwMTAwMDBkMDEwMTYyODY4YTcwMWJlNzFhYzE5OWFjNmRhODE3MWYwZTQyZjM0YTU5ZGUyN2IyM2ZjYmEzMDBmMDdmZDJlMzZjMmMifQ==';
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

  it('verifies wallet ownership with provided signer function', async () => {
    await expect(verify('undefined', proofJWTFixture, { message }, currentTimeNsOverride, iiCanisterIdOverride)).resolves.not.toThrow();
  });

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