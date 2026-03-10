## `expo-device-crypto`

> ⚠️ This module is currently in beta and is not suitable for production use.

Hardware-backed cryptography for Expo apps using Android Keystore and Apple Secure Enclave/Keychain where available.

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

### ECDSA (`ECDSA_SECP256R1_SHA256`)

- **Type:** Digital signature algorithm (asymmetric).
- **Curve:** P-256 / secp256r1.
- **Hash:** SHA-256.
- **Use it for:** Authentication challenges, message signing, and tamper detection.

### RSA (`RSA_2048_PKCS1`)

- **Type:** Asymmetric encryption algorithm.
- **Key size:** 2048 bits.
- **Padding:** PKCS#1 v1.5.
- **Use it for:** Encrypting small secrets that only the private key holder should decrypt.

## Biometric and Passcode Protection

You can bind private key usage to user authentication with:

- `requireAuthentication: true` when creating a key pair. (set to `false` to allow signing and decryption without authentication prompts)
- Use `AuthMethod.PASSCODE` or `AuthMethod.PASSCODE_OR_BIOMETRIC` to specify whether authentication should require only a passcode or allow biometrics when available.

Before using authentication-protected keys, verify that device authentication is available. If the user has not enabled at least a passcode, this function returns `AuthCheckResult.UNAVAILABLE`.

```ts
import DeviceCrypto, { AuthCheckResult } from "expo-device-crypto";

const authStatus = DeviceCrypto.isAuthCheckAvailable();
if (authStatus !== AuthCheckResult.AVAILABLE) {
  throw new Error(`Authentication unavailable: ${authStatus}`);
}
```

## Example: ECDSA with Biometric

```ts
import DeviceCrypto, {
  AuthMethod,
  SigningAlgorithm,
} from "expo-device-crypto";

const alias = "user-signing-key";
const payload = "Sign this challenge payload";
const algorithmType = SigningAlgorithm.ECDSA_SECP256R1_SHA256;
const authMethod = AuthMethod.PASSCODE_OR_BIOMETRIC;

// 1) Generate an auth-protected ECDSA key pair
await DeviceCrypto.generateKeyPair(alias, {
  requireAuthentication: true,
  authMethod, // iOS: defined at key generation;
  algorithmType,
});

// 2) Optional: share public key with backend
const publicKeyPem = DeviceCrypto.getPublicKey(alias, { format: "PEM" });

// 3) Sign with private key (prompts biometric/passcode on protected keys)
// Note: The data to sign must be in UTF-8 format.
const signature = await DeviceCrypto.sign(alias, payload, {
  algorithmType,
  authMethod, // Android: defined when signing
});

// 4) Verify locally (usually done server-side with stored public key)
const isValid = await DeviceCrypto.verify(alias, payload, signature ?? "", {
  algorithmType,
});
```

## Example: RSA with Biometric

```ts
import DeviceCrypto, {
  AuthMethod,
  EncryptionAlgorithm,
} from "expo-device-crypto";

const alias = "user-encryption-key";
const secret = "Sensitive token";
const algorithmType = EncryptionAlgorithm.RSA_2048_PKCS1;
const authMethod = AuthMethod.PASSCODE_OR_BIOMETRIC;

// 1) Generate an auth-protected RSA key pair
await DeviceCrypto.generateKeyPair(alias, {
  algorithmType,
  requireAuthentication: true,
  authMethod, // iOS: defined at key generation;
});

// 2) Optional: retrieve/share public key with backend
const publicKeyPem = DeviceCrypto.getPublicKey(alias, { format: "PEM" });

// 3) Encrypt with public key
const encrypted = await DeviceCrypto.encrypt(alias, secret, {
  algorithmType,
});

// 4) Decrypt with private key (prompts biometric/passcode on protected keys)
// Note: Data to encrypt must be in Base64 format.
const decrypted = await DeviceCrypto.decrypt(alias, encrypted ?? "", {
  algorithmType,
  authMethod, // Android: defined when decrypting
});
```

