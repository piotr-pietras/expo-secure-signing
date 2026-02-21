## `expo-secure-signing`

> ⚠️ Please note that the module is currently in beta and is not suitable for production.

Secure, device-backed **ECDSA P‑256 signing** for Expo / React Native apps.

This module stores private keys in the platform’s protected key storage:

- **Android**: backed by the **Android Keystore system** ([docs](https://developer.android.com/privacy-and-security/keystore)). When available, it prefers **StrongBox**.
- **iOS**: backed by the **Secure Enclave** ([docs](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)).

The private key never leaves the keystore / secure hardware; the module only exposes **public key export**, **sign**, and **verify** operations.

## Platform support

- **iOS**: iOS 15.1+
- **Android**: minSdk 24+
- **Expo Go**: not supported (requires a native build / custom dev client)

## Installation

Install the package in your app:

```bash
npx expo install expo-secure-signing
```

## Usage **without** biometric/passcode authentication

```ts
import SecureSigning, {
  AuthCheckResult,
  GenerateKeyPairResult,
  SignMethod,
} from "expo-secure-signing";

const alias = "my-key";

// 1) Create (or reuse) a device-backed P‑256 key pair
const res = await SecureSigning.generateKeyPair(alias);
if (res === GenerateKeyPairResult.NOT_AVAILABLE) {
  throw new Error("Secure signing is not available on this device.");
}

// 2) Export the public key
// - Default: Base64 of DER SubjectPublicKeyInfo (SPKI)
// - Optional: PEM (-----BEGIN PUBLIC KEY----- ...), wrapped at 64 chars/line
const publicKey = SecureSigning.getPublicKey(alias, { format: "PEM" });
if (!publicKey) throw new Error("Missing key");

// 3) Sign and verify (signature is Base64-encoded DER ECDSA signature)
const message = "hello";
const signatureBase64 = await SecureSigning.sign(alias, message);
if (!signatureBase64) throw new Error("Signing failed");
const ok = SecureSigning.verify(alias, message, signatureBase64);
```

## Usage **with** biometric/passcode authentication

```ts
import SecureSigning, {
  AuthCheckResult,
  GenerateKeyPairResult,
  SignMethod,
} from "expo-secure-signing";

const alias = "my-auth-key";

// Optional but recommended: check auth capability first
const authStatus = SecureSigning.isAuthCheckAvailable();
if (authStatus !== AuthCheckResult.AVAILABLE) {
  throw new Error(`Authentication not available: ${authStatus}`);
}

const created = await SecureSigning.generateKeyPair(alias, {
  requireAuthentication: true,
  // iOS: choose auth method when generating the key.
  authMethod: SignMethod.PASSCODE_OR_BIOMETRIC,
});

if (
  created === GenerateKeyPairResult.NOT_AVAILABLE
) {
  throw new Error("Secure signing is not available on this device.");
}

const signature = await SecureSigning.sign(alias, "sensitive payload", {
  // Android: choose auth method and optional prompt text when signing.
  authMethod: SignMethod.PASSCODE_OR_BIOMETRIC,
  promptTitle: "Sign message",
  promptSubtitle: "Authenticate to continue",
});
```

If you want to allow Face ID on iOS, add `NSFaceIDUsageDescription` in your app config:

```json
{
  "ios": {
    "infoPlist": {
      "NSFaceIDUsageDescription": "We use Face ID to secure your data."
    }
  }
}
```

## API (all exposed functions)

The default export is the native module instance:

```ts
import SecureSigning from "expo-secure-signing";
```

### `isAuthCheckAvailable(): AuthCheckResult`

Checks if biometric/passcode authentication is available on the current device.

- **Returns**:
  - `AuthCheckResult.AVAILABLE`
  - `AuthCheckResult.NO_HARDWARE`
  - `AuthCheckResult.UNAVAILABLE`

### `generateKeyPair(alias: string, options?: GenerateKeyPairOptions): Promise<GenerateKeyPairResult>`

Creates a new **ECDSA P‑256** key pair for the given `alias`, if it doesn’t already exist.

- **Returns**:
  - `GenerateKeyPairResult.KEY_PAIR_GENERATED`
  - `GenerateKeyPairResult.KEY_PAIR_ALREADY_EXISTS`
  - `GenerateKeyPairResult.NOT_AVAILABLE` (e.g. secure hardware / keystore APIs not available)

- **Options**:
  - `requireAuthentication?: boolean` (default: `false`)
  - `authMethod?: SignMethod` (default: `SignMethod.PASSCODE_OR_BIOMETRIC`, iOS)

### `getPublicKey(alias: string, options?: { format?: "DER" | "PEM" }): string | null`

Returns the public key for `alias`, or `null` if the key doesn’t exist.

### `removeKeyPair(alias: string): boolean`

Deletes the key pair for `alias`.

- **Returns**: `true` if the entry existed and was deleted, otherwise `false`.

### `aliases(): string[]`

Lists aliases currently stored by the platform keystore/keychain for this key type.

### `sign(alias: string, data: string, options?: SignOptions): Promise<string | null>`

Signs `data` with the private key stored under `alias`.

- **Algorithm**: ECDSA P‑256 with SHA‑256 (`SHA256withECDSA`)
- **Input**: `data` is treated as a UTF‑8 string message
- **Returns**: Base64 of the DER/X9.62 encoded ECDSA signature, or `null` if key is missing

- **Options**:
  - `promptTitle?: string` (default: `"Unlock"`, Android)
  - `promptSubtitle?: string` (default: `"Enter your PIN to continue"`, Android)
  - `authMethod?: SignMethod` (default: `SignMethod.PASSCODE_OR_BIOMETRIC`, Android)

If the key doesn’t exist, native code returns `null` (which may surface as a runtime error in JS). Ensure you call `generateKeyPair()` first and/or check `getPublicKey()` before signing.

### `verify(alias: string, data: string, signature: string): boolean | null`

Verifies a Base64 signature for `data` using the key pair under `alias`.

- **Returns**:
  - `true` / `false` if the key exists and verification ran
  - `null` if the key doesn’t exist

## Data formats

- **Public key**: Base64 of DER SPKI for P‑256 (portable to most crypto libraries).
- **Signature**: Base64 of DER/X9.62 ECDSA signature (ASN.1 sequence of `r` and `s`).
