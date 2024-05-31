import { Wallet } from 'ethers';
import { create, verify } from '../src';

const expired = {
  address: '0x33A17d5f19827EB220a3C05e33E5678A8b7b45Eb',
  proof:
    'eyJleHBpcmVzIjoiMjAyMy0wNS0wNFQxMzoyODoxNy45MThaIiwibWVzc2FnZSI6InRlc3QifQ==.MHhiMmEyZmQ5MWFiMDNkYzQwN2UwMjIxZDdhMjVlOGY5ZDIzNmI5Y2U1NGYxODA1MDVjYjE2NWYwMmMyMDQxMTBkNzhkNDRhMTQzMWY4NTI3YWY2OGZjZTg1MWRjZmI2ZDcwYzA5NjVmN2FlNGM2NWYyYjcwZDRkOWU4MjBlOWRiOTFj',
};

describe('prove-icp-principal', () => {
  afterEach(() => jest.restoreAllMocks());

  let wallet: Wallet;
  let message: string;
  beforeEach(() => {
    message = 'test';
    wallet = Wallet.createRandom();
  });

  it('creates a wallet ownership proof when a signer function is provided', async () => {
    const proof = await create((...args) => wallet._signTypedData(...args), {
      message,
    });
    expect(proof).toMatch(/.*\..*/); // the message is a base64 version of the signature concatenated with the message
  });

  it('verifies wallet ownership with provided signer function', async () => {
    const proof = await create((...args) => wallet._signTypedData(...args), {
      message,
    });
    await expect(verify(wallet.address, proof, { message })).resolves.not.toThrow();
  });

  it('throws an error if the transaction is signed with a different key', async () => {
    const someOtherKey = Wallet.createRandom();

    const proof = await create((...args) => wallet._signTypedData(...args), {
      message,
    });
    await expect(verify(someOtherKey.address, proof, { message })).rejects.toThrow();
  });

  it('throws an error if the proof is expired', async () => {
    await expect(verify(expired.address, expired.proof, { message: 'test' })).rejects.toThrow('Token Expired');
  });

  it("throws an error if the message doesn't match", async () => {
    const proof = await create((...args) => wallet._signTypedData(...args), {
      message: 'bad',
    });
    await expect(verify(wallet.address, proof, { message: 'test' })).rejects.toThrow('Bad message');
  });

  it("throws an error if the verifierAddress doesn't match", async () => {
    const proof = await create((...args) => wallet._signTypedData(...args), {
      verifierAddress: 'bad',
      types: {
        PoWo: [
          { name: 'expires', type: 'string' },
          { name: 'verifierAddress', type: 'string' },
        ],
      },
    });
    await expect(
      verify(wallet.address, proof, {
        verifierAddress: 'test',
        types: {
          PoWo: [
            { name: 'expires', type: 'string' },
            { name: 'verifierAddress', type: 'string' },
          ],
        },
      })
    ).rejects.toThrow('Bad verifier address');
  });

  it('verifies wallet ownership when only verifier address is passed', async () => {
    const proof = await create((...args) => wallet._signTypedData(...args), {
      verifierAddress: 'good',
      types: {
        PoWo: [
          { name: 'expires', type: 'string' },
          { name: 'verifierAddress', type: 'string' },
        ],
      },
    });
    await expect(
      verify(wallet.address, proof, {
        verifierAddress: 'good',
        types: {
          PoWo: [
            { name: 'expires', type: 'string' },
            { name: 'verifierAddress', type: 'string' },
          ],
        },
      })
    ).resolves.not.toThrow();
  });
});
