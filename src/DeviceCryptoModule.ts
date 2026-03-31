import { NativeModule, requireNativeModule } from "expo";

import {
  AuthCheckResult,
  GenerateKeyPairOptions,
  GenerateKeyPairResult,
  GetPublicKeyOptions,
  AuthMethod,
  SignOptions,
  DecryptOptions,
  VerifyOptions,
  SigningAlgorithm,
  EncryptOptions,
  EncryptionAlgorithm,
} from "./DeviceCrypto.types";

function base64ToPem(base64: string, label = "DATA") {
  const normalized = base64.replace(/\s+/g, "");
  const wrapped = normalized.match(/.{1,64}/g)?.join("\n") ?? "";

  return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----\n`;
}

declare class DeviceCryptoModule extends NativeModule {
  isAuthCheckAvailable(): AuthCheckResult;
  isStrongBoxAvailable(): boolean;
  generateKeyPair(alias: string, o: any): GenerateKeyPairResult;
  getPublicKey(alias: string): string | null;
  removeKeyPair(alias: string): boolean;
  aliases(): string[];
  sign(alias: string, data: string, o: any): Promise<string | null>;
  verify(
    alias: string,
    data: string,
    signature: string,
    o: any
  ): boolean | null;
  encrypt(alias: string, data: string, o: any): Promise<string | null>;
  decrypt(alias: string, data: string, o: any): Promise<string | null>;
}

const module = requireNativeModule<DeviceCryptoModule>("DeviceCrypto");

export default {
  /**
   * Checks if the biometric or passcode authentication is available.
   * @returns The result of the operation.
   */
  isAuthCheckAvailable: module.isAuthCheckAvailable,
  /**
   * Checks if the strong box is available .
   * @returns The result of the operation.
   * @platform android 🤖
   */
  isStrongBoxAvailable: module.isStrongBoxAvailable,
  /**
   * Creates a new ECDSA P‑256 key pair for the given alias, if it doesn’t already exist.
   * @param alias - The alias to use for the key pair.
   * @returns The result of the operation.
   */
  generateKeyPair: async (alias: string, options?: GenerateKeyPairOptions) => {
    const o = {
      algoType: options?.algorithmType,
      reqAuth: options?.requireAuthentication ?? false,
      authMethod: options?.authMethod ?? AuthMethod.PASSCODE_OR_BIOMETRIC,
      preferStrongBox: options?.preferStrongBox ?? false,
    };
    return module.generateKeyPair(alias, o);
  },
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
    } else if (options?.format === "BASE64") {
      return publicKey;
    }

    return base64ToPem(publicKey, "PUBLIC KEY");
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
   * @param options - The options for the operation.
   * @returns The signature.
   */
  sign: async (alias: string, data: string, options?: SignOptions) => {
    const o = {
      title: options?.promptTitle ?? "Unlock",
      subtitle: options?.promptSubtitle ?? "Enter your PIN to continue",
      authMethod: options?.authMethod ?? AuthMethod.PASSCODE_OR_BIOMETRIC,
      algoType:
        options?.algorithmType ?? SigningAlgorithm.ECDSA_SECP256R1_SHA256,
    };
    return module.sign(alias, data, o);
  },
  /**
   * Verifies the given data with the signature for the given alias.
   * @param alias - The alias to use for the key pair.
   * @param data - The data to verify in UTF-8 format.
   * @param signature - The signature to verify in Base64 format.
   * @param options - The options for the operation.
   * @returns True if the signature is valid, false otherwise.
   */
  verify: async (
    alias: string,
    data: string,
    signature: string,
    options?: VerifyOptions
  ) => {
    const o = {
      algoType:
        options?.algorithmType ?? SigningAlgorithm.ECDSA_SECP256R1_SHA256,
    };
    return module.verify(alias, data, signature, o);
  },
  /**
   * Signs the given data with the private key for the given alias.
   * @param alias - The alias to use for the key pair.
   * @param data - The data to sign in UTF-8 format.
   * @param options - The options for the operation.
   * @default {
   *  algoType: EncryptionAlgorithm.RSA_2048_PKCS1,
   * }
   * @returns The signature.
   */
  encrypt: async (alias: string, data: string, options?: EncryptOptions) => {
    const o = {
      algoType: options?.algorithmType ?? EncryptionAlgorithm.RSA_2048_PKCS1,
      peerPublicKey: options?.peerPublicKey ?? "",
    };
    return module.encrypt(alias, data, o);
  },
  /**
   * Decrypts the given data with the private key for the given alias.
   * @param alias - The alias to use for the key pair.
   * @param data - The data to decrypt in Base64 format.
   * @param options - The options for the operation.
   * @returns The decrypted data.
   */
  decrypt: async (alias: string, data: string, options?: DecryptOptions) => {
    const o = {
      title: options?.promptTitle ?? "Unlock",
      subtitle: options?.promptSubtitle ?? "Enter your PIN to continue",
      authMethod: options?.authMethod ?? AuthMethod.PASSCODE_OR_BIOMETRIC,
      algoType: options?.algorithmType ?? EncryptionAlgorithm.RSA_2048_PKCS1,
      peerPublicKey: options?.peerPublicKey ?? "",
    };
    return module.decrypt(alias, data, o);
  },
};
