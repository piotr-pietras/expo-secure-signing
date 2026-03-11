## `expo-device-crypto`

> ⚠️ This module is currently in beta and is not suitable for production use.

🔒 Hardware-backed cryptography for Expo apps using [Android Keystore](https://developer.android.com/privacy-and-security/keystore) and Apple [Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)/Keychain where available.

## Installation

```bash
npx expo install expo-device-crypto
```

If you want to allow Face ID on iOS, add this to your app config:

```json
{
  "expo": {
    "ios": {
      "infoPlist": {
        "NSFaceIDUsageDescription": "We use Face ID to protect your cryptographic keys."
      }
    }
  }
}
```

## Supported Algorithms

### Signature Algorithms

- #### `ECDSA_SECP256R1_SHA256`

**Curve:** P-256 / secp256r1. </br>
**Hash:** SHA-256. </br>
**Use it for:** Authentication challenges, message signing, and tamper detection.

### Encryption Algorithms

- #### `RSA_2048_PKCS1`

**Key size:** 2048 bits. </br>
**Padding:** PKCS#1 v1.5. </br>
**Use it for:** Encrypting small secrets that only the private key holder should decrypt.

More coming soon 

## Example: ECDSA with Biometric

```ts
import DeviceCrypto, {
  AuthCheckResult,
  AuthMethod,
  SigningAlgorithm,
} from "expo-device-crypto";

const alias = "user-signing-key";
const payload = "Sign this challenge payload";
const algorithmType = SigningAlgorithm.ECDSA_SECP256R1_SHA256;
const authMethod = AuthMethod.PASSCODE_OR_BIOMETRIC;

// 1) Ensure device authentication is configured (passcode at minimum)
const authStatus = DeviceCrypto.isAuthCheckAvailable();
if (authStatus !== AuthCheckResult.AVAILABLE) {
  throw new Error(`Authentication unavailable: ${authStatus}`);
}

// 2) Generate an auth-protected ECDSA key pair
await DeviceCrypto.generateKeyPair(alias, {
  requireAuthentication: true,
  authMethod, // iOS: defined at key generation;
  algorithmType,
});

// 3) Optional: share public key with backend
const publicKeyPem = DeviceCrypto.getPublicKey(alias, { format: "PEM" });

// 4) Sign with private key (prompts biometric/passcode on protected keys)
// Note: The data to sign must be in UTF-8 format.
// Note: This function should display the system user authentication prompt.
const signature = await DeviceCrypto.sign(alias, payload, {
  algorithmType,
  authMethod, // Android: defined when signing
});

// 5) Verify locally (usually done server-side with stored public key)
const isValid = await DeviceCrypto.verify(alias, payload, signature ?? "", {
  algorithmType,
});
```

## Example: RSA with Biometric

```ts
import DeviceCrypto, {
  AuthCheckResult,
  AuthMethod,
  EncryptionAlgorithm,
} from "expo-device-crypto";

const alias = "user-encryption-key";
const secret = "Sensitive token";
const algorithmType = EncryptionAlgorithm.RSA_2048_PKCS1;
const authMethod = AuthMethod.PASSCODE_OR_BIOMETRIC;

// 1) Ensure device authentication is configured (passcode at minimum)
const authStatus = DeviceCrypto.isAuthCheckAvailable();
if (authStatus !== AuthCheckResult.AVAILABLE) {
  throw new Error(`Authentication unavailable: ${authStatus}`);
}

// 2) Generate an auth-protected RSA key pair
await DeviceCrypto.generateKeyPair(alias, {
  algorithmType,
  requireAuthentication: true,
  authMethod, // iOS: defined at key generation;
});

// 3) Optional: retrieve/share public key with backend
const publicKeyPem = DeviceCrypto.getPublicKey(alias, { format: "PEM" });

// 4) Encrypt with public key
const encrypted = await DeviceCrypto.encrypt(alias, secret, {
  algorithmType,
});

// 5) Decrypt with private key (prompts biometric/passcode on protected keys)
// Note: Data to decrypt must be in Base64 format.
// Note: This function should display the system user authentication prompt.
const decrypted = await DeviceCrypto.decrypt(alias, encrypted ?? "", {
  algorithmType,
  authMethod, // Android: defined when decrypting
});
```

> ⚠️ Because iOS Keychain/Secure Enclave binds authentication policy to key creation, `authMethod` must be set in `generateKeyPair`. On Android Keystore, authentication is applied at key usage time, so `authMethod` is provided in operations like `sign` and `decrypt`.

### Methods

- `isAuthCheckAvailable(): AuthCheckResult`
  - Returns device authentication availability (`AVAILABLE`, `NO_HARDWARE`, `UNAVAILABLE`).

- `generateKeyPair(alias: string, options?: GenerateKeyPairOptions): Promise<GenerateKeyPairResult>`
  - Creates a key pair for `alias` if it does not exist.
  - Defaults: `requireAuthentication = false`, `authMethod = PASSCODE_OR_BIOMETRIC`.

- `getPublicKey(alias: string, options?: GetPublicKeyOptions): string | null`
  - Returns public key in PEM format (or `null` if alias not found).
  - Defaults: `format = "PEM"`.

- `removeKeyPair(alias: string): boolean`
  - Removes the key pair for the alias.

- `aliases(): string[]`
  - Lists stored key aliases.

- `sign(alias: string, data: string, options?: SignOptions): Promise<string | null>`
  - Signs UTF-8 `data` with private key.
  - Defaults: `algorithmType = ECDSA_SECP256R1_SHA256`, `promptTitle = "Unlock"`, `promptSubtitle = "Enter your PIN to continue"`, `authMethod = PASSCODE_OR_BIOMETRIC`.

- `verify(alias: string, data: string, signature: string, options?: VerifyOptions): Promise<boolean | null>`
  - Verifies signature for UTF-8 `data`.
  - Signature must be in Base64 format.
  - Default: `algorithmType = ECDSA_SECP256R1_SHA256`.

- `encrypt(alias: string, data: string, options?: EncryptOptions): Promise<string | null>`
  - Encrypts UTF-8 `data` with public key.
  - Default: `algorithmType = RSA_2048_PKCS1`.

- `decrypt(alias: string, data: string, options?: DecryptOptions): Promise<string | null>`
  - Decrypts Base64 `data` with private key.
  - Defaults: `algorithmType = RSA_2048_PKCS1`, `promptTitle = "Unlock"`, `promptSubtitle = "Enter your PIN to continue"`, `authMethod = PASSCODE_OR_BIOMETRIC`.

> ✅ JSDoc type definitions are available in `./src/DeviceCryptoModule.ts`.