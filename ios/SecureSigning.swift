import ExpoModulesCore
import Security
import Foundation
import LocalAuthentication

enum SecureSigningModuleResult: String {
  case KEY_PAIR_GENERATED = "KEY_PAIR_GENERATED"
  case KEY_PAIR_ALREADY_EXISTS = "KEY_PAIR_ALREADY_EXISTS"
  case NOT_AVAILABLE = "NOT_AVAILABLE"
}

enum SignMethod: String {
  case PASSCODE = "PASSCODE"
  case PASSCODE_OR_BIOMETRIC = "PASSCODE_OR_BIOMETRIC"
}

public class SecureSigningModule: Module {
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

  private func isAuthCheckAvailable() -> Bool {
    let context = LAContext()
    return context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
  }

  private func getAliases() -> [String] {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecMatchLimit as String: kSecMatchLimitAll,
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
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

  private func getSecKeyQuery(_ alias: String) -> [String: Any] {
    return [
      kSecClass as String: kSecClassKey,
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrApplicationTag as String: alias,
      kSecReturnRef as String: true,
    ]
  }

  private func getSecKeyByAlias(_ alias: String) -> SecKey? {
    let query: [String: Any] = self.getSecKeyQuery(alias)
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess else { return nil }
    return (item as! SecKey)
  }

  private func retrievePublicKey(_ secKey: SecKey) -> String? {
    let publicKey = SecKeyCopyPublicKey(secKey)!
    let spkiDER = x962ECPointToP256SPKI(publicKey)!
    return spkiDER.base64EncodedString()
  }

  private func removeKeyStoreEntry(_ alias: String) -> Bool {
    let secKey = self.getSecKeyByAlias(alias)
    if secKey == nil { return false }

    let query = self.getSecKeyQuery(alias)
    let status = SecItemDelete(query as CFDictionary)
    return status == errSecSuccess
  }

  public func definition() -> ModuleDefinition {

    Name("SecureSigning")

    Function("isAuthCheckAvailable") { () -> Bool in
      return self.isAuthCheckAvailable()
    }

    Function("generateKeyPair") { (alias: String, o: [String: Any]) -> String in
      let reqAuth = o["reqAuth"] as! Bool
      let authMethod = SignMethod(rawValue: o["authMethod"] as! String)

      if reqAuth && !self.isAuthCheckAvailable() {
        throw NSError(
          domain: "SecureSigning",
          code: 1,
          userInfo: [NSLocalizedDescriptionKey: "NO_AUTH_AVAILABLE"]
        )
      }

      let secKey = self.getSecKeyByAlias(alias)
      if secKey != nil {
        return SecureSigningModuleResult.KEY_PAIR_ALREADY_EXISTS.rawValue
      }

      let accessFlags: SecAccessControlCreateFlags
      if reqAuth {
        switch authMethod {
          case .PASSCODE:
            accessFlags = [.privateKeyUsage, .devicePasscode]
          case .PASSCODE_OR_BIOMETRIC:
            accessFlags = [.privateKeyUsage, .userPresence]
          default:
            accessFlags = .privateKeyUsage
        }
      } else {
        accessFlags = .privateKeyUsage
      }

      guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlocked,
        accessFlags,
        nil
      ) else {
        return SecureSigningModuleResult.NOT_AVAILABLE.rawValue
      }

      let attributes: NSDictionary = [
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits: 256,
        kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs: [
            kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: alias,
            kSecAttrAccessControl: access
        ]
      ]

      SecKeyCreateRandomKey(attributes, nil)
      return SecureSigningModuleResult.KEY_PAIR_GENERATED.rawValue
    }

    Function("removeKeyPair") { (alias: String) -> Bool in
      return self.removeKeyStoreEntry(alias)
    }

    Function("aliases") { () -> [String] in
      return self.getAliases()
    }

    Function("getPublicKey") { (alias: String) -> String? in
      let secKey = self.getSecKeyByAlias(alias)
      guard let secKey else { return nil }
      return self.retrievePublicKey(secKey)
    }

    AsyncFunction("sign") { (alias: String, data: String, o: [String: Any]) -> String? in
      let secKey = self.getSecKeyByAlias(alias)
      guard let secKey else { return nil }

      var signingError: Unmanaged<CFError>?
      let signatureCF = SecKeyCreateSignature(
        secKey,
        .ecdsaSignatureMessageX962SHA256,
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

    Function("verify") { (alias: String, data: String, signature: String) -> Bool? in
      let secKey = self.getSecKeyByAlias(alias)
      guard let secKey else { return nil }

      guard let publicKey = SecKeyCopyPublicKey(secKey) else { return nil }
      guard let signatureData = Data(base64Encoded: signature) else { return nil }

      let valid = SecKeyVerifySignature(
        publicKey,
        .ecdsaSignatureMessageX962SHA256,
        Data(data.utf8) as CFData,
        signatureData as CFData,
        nil
      )
      return valid
    }
  }
}
