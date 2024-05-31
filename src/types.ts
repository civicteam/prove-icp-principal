import { TypedDataDomain, TypedDataField } from '@ethersproject/abstract-signer';

export type Address = string;

export type EthPowoMessage = {
  expires: string;
  message?: string;
  verifierAddress?: string;
};

export const defaultDomain: TypedDataDomain = {
  name: 'Proof Of ICP Principal Ownership',
  version: '1',
};

export const defaultTypes: Record<string, Array<TypedDataField>> = {
  PoWo: [
    { name: 'expires', type: 'string' },
    { name: 'message', type: 'string' },
  ],
};

export type CreatePowoOptions = {
  domain?: TypedDataDomain;
  types?: Record<string, TypedDataField[]>;
  message?: string;
  verifierAddress?: string;
};
export type VerifyPowoOptions = {
  domain?: TypedDataDomain;
  types?: Record<string, TypedDataField[]>;
  message?: string;
  verifierAddress?: string;
};
