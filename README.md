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

## Usage

```ts
import SecureSigning, { GenerateKeyPairResult } from "expo-secure-signing";

const alias = "my-key";

// 1) Create (or reuse) a device-backed P‑256 key pair
const res = SecureSigning.generateKeyPair(alias);
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
const signatureBase64 = SecureSigning.sign(alias, message);
const ok = SecureSigning.verify(alias, message, signatureBase64);
```

## API (all exposed functions)

The default export is the native module instance:

```ts
import SecureSigning from "expo-secure-signing";
```

### `generateKeyPair(alias: string): GenerateKeyPairResult`

Creates a new **ECDSA P‑256** key pair for the given `alias`, if it doesn’t already exist.

- **Returns**:
  - `GenerateKeyPairResult.KEY_PAIR_GENERATED`
  - `GenerateKeyPairResult.KEY_PAIR_ALREADY_EXISTS`
  - `GenerateKeyPairResult.NOT_AVAILABLE` (e.g. secure hardware / keystore APIs not available)

### `getPublicKey(alias: string, options?: { format?: "DER" | "PEM" }): string | null`

Returns the public key for `alias`, or `null` if the key doesn’t exist.

### `removeKeyPair(alias: string): boolean`

Deletes the key pair for `alias`.

- **Returns**: `true` if the entry existed and was deleted, otherwise `false`.

### `aliases(): string[]`

Lists aliases currently stored by the platform keystore/keychain for this key type.

### `sign(alias: string, data: string): string`

Signs `data` with the private key stored under `alias`.

- **Algorithm**: ECDSA P‑256 with SHA‑256 (`SHA256withECDSA`)
- **Input**: `data` is treated as a UTF‑8 string message
- **Returns**: Base64 of the DER/X9.62 encoded ECDSA signature

If the key doesn’t exist, native code returns `null` (which may surface as a runtime error in JS). Ensure you call `generateKeyPair()` first and/or check `getPublicKey()` before signing.

### `verify(alias: string, data: string, signature: string): boolean | null`

Verifies a Base64 signature for `data` using the key pair under `alias`.

- **Returns**:
  - `true` / `false` if the key exists and verification ran
  - `null` if the key doesn’t exist

## Data formats

- **Public key**: Base64 of DER SPKI for P‑256 (portable to most crypto libraries).
- **Signature**: Base64 of DER/X9.62 ECDSA signature (ASN.1 sequence of `r` and `s`).
