import { NativeModule, requireNativeModule } from "expo";

import {
  GenerateKeyPairResult,
  GetPublicKeyOptions,
} from "./SecureSigning.types";

function base64ToPem(base64: string, label = "DATA") {
  const normalized = base64.replace(/\s+/g, "");
  const wrapped = normalized.match(/.{1,64}/g)?.join("\n") ?? "";

  return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----\n`;
}

declare class SecureSigningModule extends NativeModule {
  generateKeyPair(alias: string): GenerateKeyPairResult;
  getPublicKey(alias: string): string | null;
  removeKeyPair(alias: string): boolean;
  aliases(): string[];
  sign(alias: string, data: string): string;
  verify(alias: string, data: string, signature: string): boolean | null;
}

const module = requireNativeModule<SecureSigningModule>("SecureSigning");

export default {
  /**
   * Creates a new ECDSA P‑256 key pair for the given alias, if it doesn’t already exist.
   * @param alias - The alias to use for the key pair.
   * @returns The result of the operation.
   */
  generateKeyPair: module.generateKeyPair,
  /**
   * Returns the public key for the given alias.
   * @param alias - The alias to use for the key pair.
   * @param options - The options for the operation.
   * @returns The public key.
   */
  getPublicKey: (alias: string, options?: GetPublicKeyOptions) => {
    const publicKey = module.getPublicKey(alias);
    if (!publicKey) return null;
    if (options?.format === "PEM") {
      return base64ToPem(publicKey, "PUBLIC KEY");
    }
    return publicKey;
  },
  /**
   * Removes the key pair for the given alias.
   * @param alias - The alias to use for the key pair.
   * @returns True if the key pair was removed, false otherwise.
   */
  removeKeyPair: module.removeKeyPair,
  /**
   * Lists the aliases for the key pairs.
   * @returns The aliases.
   */
  aliases: module.aliases,
  /**
   * Signs the given data with the private key for the given alias.
   * @param alias - The alias to use for the key pair.
   * @param data - The data to sign.
   * @returns The signature.
   */
  sign: module.sign,
  /**
   * Verifies the given data with the signature for the given alias.
   * @param alias - The alias to use for the key pair.
   * @param data - The data to verify.
   * @param signature - The signature to verify.
   * @returns True if the signature is valid, false otherwise.
   */
  verify: module.verify,
};

export type { GenerateKeyPairResult };
