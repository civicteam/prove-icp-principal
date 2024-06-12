export type Address = string;

export type ICPPowoMessage = {
  expires: string;
  message?: string;
  verifierAddress?: string;
};

export type CreatePowoOptions = {
  message?: string;
  verifierAddress?: string;
};
export type VerifyPowoOptions = {
  message?: string;
  verifierAddress?: string;
};
