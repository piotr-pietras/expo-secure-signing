export enum GenerateKeyPairResult {
  KEY_PAIR_GENERATED = "KEY_PAIR_GENERATED",
  KEY_PAIR_ALREADY_EXISTS = "KEY_PAIR_ALREADY_EXISTS",
  NOT_AVAILABLE = "NOT_AVAILABLE",
}

export enum AuthCheckResult {
  AVAILABLE = "AVAILABLE",
  NO_HARDWARE = "NO_HARDWARE",
  UNAVAILABLE = "UNAVAILABLE",
}

export enum SignMethod {
  PASSCODE = "PASSCODE",
  PASSCODE_OR_BIOMETRIC = "PASSCODE_OR_BIOMETRIC",
}

export interface GenerateKeyPairOptions {
  /**
   * Whether to require authentication to sign.
   * Setting this to true will prompt biometric or passcode authentication before signing.
   *
   * Please check the *`isAuthCheckAvailable`* function to see if authentication is available.
   * If authentication is not available, generating a key pair will throw an error.
   * @default false
   */
  requireAuthentication?: boolean;
  /**
   * The method of authentication to use.
   * Note that on Android you have to define it when signing.
   * 
   * If you want to allow to use Face ID, you need to add the following to your app.json config file:
   * ```json
   * "ios": {
   *   "infoPlist": {
   *     "NSFaceIDUsageDescription": "We use Face ID to secure your data.",
   *   }
   * }
   * ```
   * @default SignMethod.PASSCODE_OR_BIOMETRIC
   * @platform ios
   */
  authMethod?: SignMethod;
}

export interface SignOptions {
  /**
   * The title of the prompt to show when authentication is required.
   * @default "Unlock"
   * @platform android
   */
  promptTitle?: string;
  /**
   * The subtitle of the prompt to show when authentication is required.
   * @default "Enter your PIN to continue"
   * @platform android
   */
  promptSubtitle?: string;
  /**
   * The method of authentication to use.
   * Note that on iOS you have to define it when generating the key pair.
   * @default SignMethod.PASSCODE_OR_BIOMETRIC
   * @platform android
   */
  authMethod?: SignMethod;
}
export interface GetPublicKeyOptions {
  /**
   * The format of the public key to return.
   * @default "DER" (Base64 of DER-encoded SubjectPublicKeyInfo (SPKI) for P‑256)
   */
  format?: "DER" | "PEM";
}
