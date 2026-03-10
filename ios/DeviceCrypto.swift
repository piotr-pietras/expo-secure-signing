import ExpoModulesCore
import Security
import Foundation
import LocalAuthentication

enum SecureSigningModuleResult: String {
  case KEY_PAIR_GENERATED = "KEY_PAIR_GENERATED"
  case KEY_PAIR_ALREADY_EXISTS = "KEY_PAIR_ALREADY_EXISTS"
  case NOT_AVAILABLE = "NOT_AVAILABLE"
}

enum AuthCheckResult: String {
  case AVAILABLE = "AVAILABLE"
  case NO_HARDWARE = "NO_HARDWARE"
  case UNAVAILABLE = "UNAVAILABLE"
}

enum AuthMethod: String {
  case PASSCODE = "PASSCODE"
  case PASSCODE_OR_BIOMETRIC = "PASSCODE_OR_BIOMETRIC"
}

enum AlgorithmType: String {
  case ECDSA_SECP256R1_SHA256 = "ECDSA_SECP256R1_SHA256"
  case RSA_2048_PKCS1 = "RSA_2048_PKCS1"
}

public class DeviceCryptoModule: Module {
  private func toiOSAlgo(algorithm: AlgorithmType) -> SecKeyAlgorithm {
    switch algorithm {
    case .ECDSA_SECP256R1_SHA256:
      return .ecdsaSignatureMessageX962SHA256
    case .RSA_2048_PKCS1:
      return .rsaEncryptionPKCS1
    }
  }

  // Converts ANSI x962 EC point to P‑256 SPKI DER format
  private func x962ECPointToP256SPKI(_ publicKey: SecKey) -> Data? {
    var error: Unmanaged<CFError>?
    guard let raw = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
      return nil
    }

    guard raw.count == 65 else { return nil }
    let prefix = Data([
      0x30, 0x59,
      0x30, 0x13,
      0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
      0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
      0x03, 0x42, 0x00
    ])
    return prefix + raw
  }

  // Converts PKCS#1 RSA public key bytes to SPKI DER format.
  private func rsaPKCS1ToSPKI(_ publicKey: SecKey) -> Data? {
    guard let pkcs1 = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
      return nil
    }

    // rsaEncryption OID: 1.2.840.113549.1.1.1 with NULL params
    let algorithmIdentifier = Data([
      0x30, 0x0D,
      0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
      0x05, 0x00
    ])

    let bitStringPayload = Data([0x00]) + pkcs1
    guard let bitString = asn1Wrap(tag: 0x03, content: bitStringPayload) else {
      return nil
    }

    return asn1Wrap(tag: 0x30, content: algorithmIdentifier + bitString)
  }

  private func asn1Wrap(tag: UInt8, content: Data) -> Data? {
    guard let length = asn1Length(content.count) else {
      return nil
    }
    return Data([tag]) + length + content
  }

  private func asn1Length(_ length: Int) -> Data? {
    if length < 0x80 {
      return Data([UInt8(length)])
    }

    var value = length
    var bytes: [UInt8] = []
    while value > 0 {
      bytes.insert(UInt8(value & 0xff), at: 0)
      value >>= 8
    }

    guard bytes.count <= 4 else {
      return nil
    }

    return Data([0x80 | UInt8(bytes.count)]) + Data(bytes)
  }

  private func isAuthCheckAvailable() -> String {
    let context = LAContext()
    let available = context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
    if available {
      return AuthCheckResult.AVAILABLE.rawValue
    } else {
      return AuthCheckResult.UNAVAILABLE.rawValue
    }
  }

  private func getAliases() -> [String] {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
      kSecMatchLimit as String: kSecMatchLimitAll,
      kSecReturnAttributes as String: true,
    ]

    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess else { return [] }

    let items = (result as? [[String: Any]]) ?? []
    return items.compactMap { attrs in
      let tagKey = kSecAttrApplicationTag as String
      if let tagString = attrs[tagKey] as? String {
        return tagString
      }
      return nil
    }
  }

  private func getSecKeyQuery(_ alias: String, keyClass: CFString, returnRef: Bool = true) -> [String: Any] {
    var query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: alias,
      kSecAttrKeyClass as String: keyClass,
    ]
    if returnRef {
      query[kSecReturnRef as String] = true
    }
    return query
  }

  private func getSecKeyByAlias(_ alias: String, keyClass: CFString) -> SecKey? {
    let query: [String: Any] = self.getSecKeyQuery(alias, keyClass: keyClass)
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess else { return nil }
    return (item as! SecKey)
  }

  private func retrievePublicKey(_ secKey: SecKey) -> String? {
    let publicKey = SecKeyCopyPublicKey(secKey)!

    guard
      let attrs = SecKeyCopyAttributes(publicKey) as? [String: Any],
      let keyType = attrs[kSecAttrKeyType as String] as? String
    else {
      return nil
    }

    if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) {
      return x962ECPointToP256SPKI(publicKey)?.base64EncodedString()
    }

    if keyType == (kSecAttrKeyTypeRSA as String) {
      return rsaPKCS1ToSPKI(publicKey)?.base64EncodedString()
    }

    guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
      return nil
    }
    return publicKeyData.base64EncodedString()
  }

  private func removeKeyStoreEntry(_ alias: String) -> Bool {
    let privateQuery = self.getSecKeyQuery(alias, keyClass: kSecAttrKeyClassPrivate, returnRef: false)
    let privateStatus = SecItemDelete(privateQuery as CFDictionary)

    let publicQuery = self.getSecKeyQuery(alias, keyClass: kSecAttrKeyClassPublic, returnRef: false)
    let publicStatus = SecItemDelete(publicQuery as CFDictionary)

    return privateStatus == errSecSuccess || publicStatus == errSecSuccess
  }

  private func buildECDSA_SECP256R1_SHA256(alias: String, reqAuth: Bool, authMethod: AuthMethod) -> SecKey? {
    let accessFlags: SecAccessControlCreateFlags
    if reqAuth {
      switch authMethod {
        case .PASSCODE:
          accessFlags = [.privateKeyUsage, .devicePasscode]
        case .PASSCODE_OR_BIOMETRIC:
          accessFlags = [.privateKeyUsage, .userPresence]
      }
    } else {
      accessFlags = .privateKeyUsage
    }

    let access = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      accessFlags,
      nil
    ) 

    let attributes: NSDictionary = [
      kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits: 256,
      kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
      kSecPrivateKeyAttrs: [
          kSecAttrIsPermanent: true,
          kSecAttrApplicationTag: alias,
          kSecAttrAccessControl: access
      ],
      kSecPublicKeyAttrs: [
          kSecAttrIsPermanent: true,
          kSecAttrApplicationTag: alias
      ]
    ]

    return SecKeyCreateRandomKey(attributes, nil)
  }

  private func buildRSA_2048_PKCS1(alias: String, reqAuth: Bool, authMethod: AuthMethod) -> SecKey? {
    let accessFlags: SecAccessControlCreateFlags
    if reqAuth {
      switch authMethod {
        case .PASSCODE:
          accessFlags = [.devicePasscode]
        case .PASSCODE_OR_BIOMETRIC:
          accessFlags = [.userPresence]
      }
    } else {
      accessFlags = []
    }

    let access = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      accessFlags,
      nil
    ) 

    let attributes: NSDictionary = [
      kSecAttrKeyType: kSecAttrKeyTypeRSA,
      kSecAttrKeySizeInBits: 2048,
      kSecPrivateKeyAttrs: [
          kSecAttrIsPermanent: true,
          kSecAttrApplicationTag: alias,
          kSecAttrAccessControl: access
      ],
      kSecPublicKeyAttrs: [
          kSecAttrIsPermanent: true,
          kSecAttrApplicationTag: alias
      ]
    ]

    return SecKeyCreateRandomKey(attributes, nil)
  }

  public func definition() -> ModuleDefinition {

    Name("DeviceCrypto")

    Function("isAuthCheckAvailable") { () -> String in
      return self.isAuthCheckAvailable()
    }

    Function("generateKeyPair") { (alias: String, o: [String: Any]) -> String in
      let reqAuth = o["reqAuth"] as! Bool
      let authMethod = AuthMethod(rawValue: o["authMethod"] as! String)
      let algoType = AlgorithmType(rawValue: o["algoType"] as! String)

      if reqAuth && self.isAuthCheckAvailable() != AuthCheckResult.AVAILABLE.rawValue {
        throw NSError(
          domain: "DeviceCrypto",
          code: 1,
          userInfo: [NSLocalizedDescriptionKey: "NO_AUTH_AVAILABLE"]
        )
      }

      let secKey = self.getSecKeyByAlias(alias, keyClass: kSecAttrKeyClassPrivate)
      if secKey != nil {
        return SecureSigningModuleResult.KEY_PAIR_ALREADY_EXISTS.rawValue
      }

      switch algoType {
        case .ECDSA_SECP256R1_SHA256:
          self.buildECDSA_SECP256R1_SHA256(alias: alias, reqAuth: reqAuth, authMethod: authMethod!)
        case .RSA_2048_PKCS1:
          self.buildRSA_2048_PKCS1(alias: alias, reqAuth: reqAuth, authMethod: authMethod!)
        default:
          throw NSError(
            domain: "DeviceCrypto",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: "INVALID_ALGORITHM_TYPE"]
          )
      }

      return SecureSigningModuleResult.KEY_PAIR_GENERATED.rawValue
    }

    Function("removeKeyPair") { (alias: String) -> Bool in
      return self.removeKeyStoreEntry(alias)
    }

    Function("aliases") { () -> [String] in
      return self.getAliases()
    }

    Function("getPublicKey") { (alias: String) -> String? in
      let secKey = self.getSecKeyByAlias(alias, keyClass: kSecAttrKeyClassPublic)
      guard let secKey else { return nil }
      return self.retrievePublicKey(secKey)
    }

    AsyncFunction("sign") { (alias: String, data: String, o: [String: Any]) -> String? in
      let secKey = self.getSecKeyByAlias(alias, keyClass: kSecAttrKeyClassPrivate)
      guard let secKey else { return nil }

      let algoType = AlgorithmType(rawValue: o["algoType"] as! String)
      let algo = self.toiOSAlgo(algorithm: algoType!)

      var signingError: Unmanaged<CFError>?
      let signatureCF = SecKeyCreateSignature(
        secKey,
        algo,
        Data(data.utf8) as CFData,
        &signingError
      )

      if let error = signingError?.takeRetainedValue() {
        throw error as Error
      }

      guard let signatureCF else { return nil }
      let signature = signatureCF as Data
      return signature.base64EncodedString()
    }

    Function("verify") { (alias: String, data: String, signature: String, o: [String: Any]) -> Bool? in
      let secKey = self.getSecKeyByAlias(alias, keyClass: kSecAttrKeyClassPrivate)
      guard let secKey else { return nil }

      guard let publicKey = SecKeyCopyPublicKey(secKey) else { return nil }
      guard let signatureData = Data(base64Encoded: signature) else { return nil }

      let algoType = AlgorithmType(rawValue: o["algoType"] as! String)
      let algo = self.toiOSAlgo(algorithm: algoType!)

      let valid = SecKeyVerifySignature(
        publicKey,
        algo,
        Data(data.utf8) as CFData,
        signatureData as CFData,
        nil
      )
      return valid
    }

    AsyncFunction("encrypt") { (alias: String, data: String, o: [String: Any]) -> String? in
      let secKey = self.getSecKeyByAlias(alias, keyClass: kSecAttrKeyClassPublic)
      guard let secKey else { return nil }
      let publicKey = SecKeyCopyPublicKey(secKey)!

      let algoType = AlgorithmType(rawValue: o["algoType"] as! String)
      let algo = self.toiOSAlgo(algorithm: algoType!)

      guard let encrypted = SecKeyCreateEncryptedData(
        publicKey,
        algo,
        Data(data.utf8) as CFData,
        nil
      ) as Data? else {
        return nil
      }

      return encrypted.base64EncodedString()
    }

    AsyncFunction("decrypt") { (alias: String, data: String, o: [String: Any]) -> String? in
      let secKey = self.getSecKeyByAlias(alias, keyClass: kSecAttrKeyClassPrivate)
      guard let secKey else { return nil }
      guard let encryptedData = Data(base64Encoded: data) else { return nil }

      let algoType = AlgorithmType(rawValue: o["algoType"] as! String)
      let algo = self.toiOSAlgo(algorithm: algoType!)

      guard let decrypted = SecKeyCreateDecryptedData(
        secKey,
        algo,
        encryptedData as CFData,
        nil
      ) as Data? else {
        return nil
      }

      return String(data: decrypted, encoding: .utf8)
    }
  }
}
