export enum GenerateKeyPairResult {
  KEY_PAIR_GENERATED = 'KEY_PAIR_GENERATED',
  KEY_PAIR_ALREADY_EXISTS = 'KEY_PAIR_ALREADY_EXISTS',
  NOT_AVAILABLE = 'NOT_AVAILABLE',
}
export interface GetPublicKeyOptions {
  /**
   * The format of the public key to return.
   * @default "DER" (Base64 of DER-encoded SubjectPublicKeyInfo (SPKI) for P‑256)
   */
  format?: "DER" | "PEM";
}
