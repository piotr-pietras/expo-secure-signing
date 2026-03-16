package expo.modules.devicecrypto

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties.AUTH_BIOMETRIC_STRONG
import android.security.keystore.KeyProperties.AUTH_DEVICE_CREDENTIAL
import android.security.keystore.KeyProperties.DIGEST_SHA1
import android.security.keystore.KeyProperties.DIGEST_SHA256
import android.security.keystore.KeyProperties.ENCRYPTION_PADDING_RSA_OAEP
import android.security.keystore.KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1
import android.security.keystore.KeyProperties.KEY_ALGORITHM_EC
import android.security.keystore.KeyProperties.KEY_ALGORITHM_RSA
import android.security.keystore.KeyProperties.PURPOSE_DECRYPT
import android.security.keystore.KeyProperties.PURPOSE_ENCRYPT
import android.security.keystore.KeyProperties.PURPOSE_SIGN
import android.security.keystore.KeyProperties.PURPOSE_VERIFY
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource


enum class GenerateKeyPairResult {
  KEY_PAIR_GENERATED,
  KEY_PAIR_ALREADY_EXISTS,
  NOT_AVAILABLE,
}

enum class AuthCheckResult {
  AVAILABLE,
  UNAVAILABLE,
  NO_HARDWARE,
}

enum class AuthMethod {
  PASSCODE,
  PASSCODE_OR_BIOMETRIC,
}

enum class AlgorithmType {
  ECDSA_SECP256R1_SHA256,
  RSA_2048_PKCS1,
  RSA_2048_OAEP_SHA1,
}

class DeviceCryptoModule : Module() {
  private fun toAndroidAlgo(algorithm: AlgorithmType): String {
    return when (algorithm) {
      AlgorithmType.ECDSA_SECP256R1_SHA256 -> "SHA256withECDSA"
      AlgorithmType.RSA_2048_PKCS1 -> "RSA/ECB/PKCS1Padding"
      AlgorithmType.RSA_2048_OAEP_SHA1 -> "RSA/ECB/OAEPwithSHA-1AndMGF1Padding"
    }
  }

  private fun getOaepSpec(algoType: AlgorithmType): AlgorithmParameterSpec? {
    return when (algoType) {
      AlgorithmType.RSA_2048_OAEP_SHA1 -> OAEPParameterSpec(
        "SHA-1",
        "MGF1",
        MGF1ParameterSpec.SHA1,
        PSource.PSpecified.DEFAULT
      )
      else -> null
    }
  }

  private fun isKeyStoreAvailable(): Boolean {
    val pm = appContext.reactContext?.packageManager ?: return false
    val appAttestKeystore = pm.hasSystemFeature(PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY)
    val hardwareKeystore = pm.hasSystemFeature(PackageManager.FEATURE_HARDWARE_KEYSTORE)
    return appAttestKeystore || hardwareKeystore
  }

  private fun isStrongBoxAvailable(): Boolean {
    val pm = appContext.reactContext?.packageManager ?: return false
    val strongboxKeystore = pm.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    return strongboxKeystore
  }

  private fun isKeyStoreRequireAuthentication(entry: KeyStore.PrivateKeyEntry): Boolean {
    val keyFactory = KeyFactory.getInstance(entry.privateKey.algorithm, "AndroidKeyStore")
    val keyInfo = keyFactory.getKeySpec(entry.privateKey, KeyInfo::class.java)
    return keyInfo.isUserAuthenticationRequired
  }

  private fun getKeyStoreEntry(alias: String): KeyStore.Entry? {
    return KeyStore.getInstance("AndroidKeyStore").apply {
      load(null)
    }.getEntry(alias, null)
  }

  private fun buildECDSA(
    alias: String, 
    digest: String,
    reqAuth: Boolean): KeyPairGenerator {
    val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
      KEY_ALGORITHM_EC,
      "AndroidKeyStore"
    )

    val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder(
      alias,
      PURPOSE_SIGN or PURPOSE_VERIFY
    ).run {
      setDigests(digest)
      setIsStrongBoxBacked(false) // TODO: Prefer strong box if available
      setUserAuthenticationRequired(reqAuth)
      if (reqAuth) {
        setUserAuthenticationParameters(
          30, // 30 seconds
          AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL
        )
      }
      build()
    }
    kpg.initialize(parameterSpec)
    return kpg
  }

  private fun buildRSA(
    alias: String, 
    digest: String?,
    padding: String,
    reqAuth: Boolean): KeyPairGenerator {
    val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
      KEY_ALGORITHM_RSA,
      "AndroidKeyStore"
    )

    val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder(
      alias,
      PURPOSE_ENCRYPT or PURPOSE_DECRYPT
    ).run {
      if (digest != null) {
        setDigests(digest)
      }
      setEncryptionPaddings(padding)
      setIsStrongBoxBacked(false) // TODO: Prefer strong box if available
      setUserAuthenticationRequired(reqAuth)
      if (reqAuth) {
        setUserAuthenticationParameters(
          30, // 30 seconds
          AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL
        )
      }
      build()
    }
    kpg.initialize(parameterSpec)
    return kpg
  }


  private fun showAuthPrompt(
    onSuccess: () -> Unit,
    onError: (String) -> Unit,
    title: String = "Unlock",
    subtitle: String = "Enter your PIN to continue",
    authMethod: AuthMethod
  ) {
    val activity = appContext.currentActivity as? FragmentActivity ?: run {
      onError("No active FragmentActivity found")
      return
    }

    activity.runOnUiThread {
      val executor = ContextCompat.getMainExecutor(activity)
      val biometricPrompt = BiometricPrompt(
        activity,
        executor,
        object : BiometricPrompt.AuthenticationCallback() {

          override fun onAuthenticationSucceeded(
            result: BiometricPrompt.AuthenticationResult
          ) {
            super.onAuthenticationSucceeded(result)
            onSuccess()
          }

          override fun onAuthenticationError(
            errorCode: Int,
            errString: CharSequence
          ) {
            super.onAuthenticationError(errorCode, errString)
            onError(errString.toString())
          }
        }
      )

      val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle(title)
        .setSubtitle(subtitle)
        .setAllowedAuthenticators(
          when (authMethod) {
            AuthMethod.PASSCODE -> DEVICE_CREDENTIAL
            AuthMethod.PASSCODE_OR_BIOMETRIC -> BIOMETRIC_STRONG or DEVICE_CREDENTIAL
          }
        )
        .build()

      biometricPrompt.authenticate(promptInfo)
    }
  }

  private fun isAuthCheckAvailable(): AuthCheckResult {
    val biometricManager = BiometricManager.from(appContext.reactContext as Context)
    return when (biometricManager.canAuthenticate(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)) {
      BiometricManager.BIOMETRIC_SUCCESS -> AuthCheckResult.AVAILABLE
      BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> AuthCheckResult.NO_HARDWARE
      BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> AuthCheckResult.UNAVAILABLE
      else -> AuthCheckResult.UNAVAILABLE
    }
  }

  private fun generateKeyPair(alias: String, o: Map<String, Any?>): GenerateKeyPairResult {
    val reqAuth = o["reqAuth"] as Boolean
    if (reqAuth && isAuthCheckAvailable() != AuthCheckResult.AVAILABLE) {
      throw Exception("NO_AUTH_AVAILABLE")
    }
    if (!isKeyStoreAvailable()) {
      return GenerateKeyPairResult.NOT_AVAILABLE
    }
    if (getKeyStoreEntry(alias) != null) {
      return GenerateKeyPairResult.KEY_PAIR_ALREADY_EXISTS
    }

    val algoType = AlgorithmType.valueOf(o["algoType"] as String)
    val kpg = when (algoType) {
      AlgorithmType.ECDSA_SECP256R1_SHA256 -> buildECDSA(alias, DIGEST_SHA256, reqAuth)
      AlgorithmType.RSA_2048_PKCS1 -> buildRSA(alias, null, ENCRYPTION_PADDING_RSA_PKCS1, reqAuth)
      AlgorithmType.RSA_2048_OAEP_SHA1 -> buildRSA(alias, DIGEST_SHA1, ENCRYPTION_PADDING_RSA_OAEP, reqAuth)
      else -> throw Exception("INVALID_ALGORITHM_TYPE")
    }

    kpg.generateKeyPair()

    return GenerateKeyPairResult.KEY_PAIR_GENERATED
  }

  private fun removeKeyStoreEntry(alias: String): Boolean {
    val ks = KeyStore.getInstance("AndroidKeyStore").apply {
      load(null)
    }
    if (ks.getEntry(alias, null) == null) return false

    ks.deleteEntry(alias)
    return true
  }

  private fun getAliases() = KeyStore.getInstance("AndroidKeyStore").apply {
    load(null)
  }.aliases().toList()

  private fun getPublicKey(alias: String): String? {
    val ks = getKeyStoreEntry(alias)
    if (ks !is KeyStore.PrivateKeyEntry) return null
    
    val publicKeyBytes: ByteArray = ks.certificate?.publicKey?.encoded ?: return null
    return Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP)
  }

  private fun sign(alias: String, data: String, o: Map<String, Any?>, promise: Promise) {
    val entry = getKeyStoreEntry(alias)
    if (entry !is KeyStore.PrivateKeyEntry) {
      promise.resolve(null)
      return
    }

    val reqAuth = isKeyStoreRequireAuthentication(entry)

    val title = o["title"] as String
    val subtitle = o["subtitle"] as String
    val authMethod = AuthMethod.valueOf(o["authMethod"] as String)
    val algoType = AlgorithmType.valueOf(o["algoType"] as String)
    val algo = toAndroidAlgo(algoType)

    if (!reqAuth) {
      val signature: ByteArray = Signature.getInstance(algo).apply {
        initSign(entry.privateKey)
        update(data.toByteArray(Charsets.UTF_8))
      }.sign()
      promise.resolve(Base64.encodeToString(signature, Base64.NO_WRAP))
      return
    } else {
      showAuthPrompt(
        onSuccess = {
          val signature: ByteArray = Signature.getInstance(algo).apply {
            initSign(entry.privateKey)
            update(data.toByteArray(Charsets.UTF_8))
          }.sign()
          promise.resolve(Base64.encodeToString(signature, Base64.NO_WRAP))
        },
        onError = { error ->
          promise.reject("ERR_AUTH_FAILED", error, null)
        },
        title = title,
        subtitle = subtitle,
        authMethod = authMethod
      )
    }
  }

  private fun verify(alias: String, data: String, signature: String, o: Map<String, Any?>): Boolean? {
    val entry = getKeyStoreEntry(alias)
    if (entry !is KeyStore.PrivateKeyEntry) return null

    val algoType = AlgorithmType.valueOf(o["algoType"] as String)
    val algo = toAndroidAlgo(algoType)

    val valid: Boolean = Signature.getInstance(algo).apply {
      initVerify(entry.certificate)
      update(data.toByteArray(Charsets.UTF_8))
    }.verify(Base64.decode(signature, Base64.NO_WRAP))
    return valid
  }

  private fun encrypt(alias: String, data: String, o: Map<String, Any?>, promise: Promise) {
    val entry = getKeyStoreEntry(alias)
    if (entry !is KeyStore.PrivateKeyEntry) {
      promise.resolve(null)
      return
    }

    val algoType = AlgorithmType.valueOf(o["algoType"] as String)
    val algo = toAndroidAlgo(algoType)
    val oaepSpec = getOaepSpec(algoType)

    val cipher = Cipher.getInstance(algo)
    if (oaepSpec != null) {
      cipher.init(Cipher.ENCRYPT_MODE, entry.certificate.publicKey, oaepSpec)
    } else {
      cipher.init(Cipher.ENCRYPT_MODE, entry.certificate.publicKey)
    }
    val encrypted: ByteArray = cipher.doFinal(data.toByteArray(Charsets.UTF_8))
    promise.resolve(Base64.encodeToString(encrypted, Base64.NO_WRAP))
  }

  private fun decrypt(alias: String, data: String, o: Map<String, Any?>, promise: Promise) {
    val entry = getKeyStoreEntry(alias)
    if (entry !is KeyStore.PrivateKeyEntry) {
      promise.resolve(null)
      return
    }

    val reqAuth = isKeyStoreRequireAuthentication(entry)

    val title = o["title"] as String
    val subtitle = o["subtitle"] as String
    val authMethod = o["authMethod"] as String
    val algoType = AlgorithmType.valueOf(o["algoType"] as String)
    val algo = toAndroidAlgo(algoType)
    val oaepSpec = getOaepSpec(algoType)

    val cipher = Cipher.getInstance(algo)
    val ciphertext = Base64.decode(data, Base64.NO_WRAP)

    if (!reqAuth) {
      if (oaepSpec != null) {
        cipher.init(Cipher.DECRYPT_MODE, entry.privateKey, oaepSpec)
      } else {
        cipher.init(Cipher.DECRYPT_MODE, entry.privateKey)
      }
      val decrypted: ByteArray = cipher.doFinal(ciphertext)
      promise.resolve(String(decrypted, Charsets.UTF_8))
      return
    } else {
      showAuthPrompt(
        onSuccess = {
          if (oaepSpec != null) {
            cipher.init(Cipher.DECRYPT_MODE, entry.privateKey, oaepSpec)
          } else {
            cipher.init(Cipher.DECRYPT_MODE, entry.privateKey)
          }
          val decrypted: ByteArray = cipher.doFinal(ciphertext)
          promise.resolve(String(decrypted, Charsets.UTF_8))
        },
        onError = { error ->
          promise.reject("ERR_AUTH_FAILED", error, null)
        },
        title = title,
        subtitle = subtitle,
        authMethod = when (authMethod) {
          "PASSCODE" -> AuthMethod.PASSCODE
          "PASSCODE_OR_BIOMETRIC" -> AuthMethod.PASSCODE_OR_BIOMETRIC
          else -> AuthMethod.PASSCODE_OR_BIOMETRIC
        }
      )
    }
  }

  override fun definition() = ModuleDefinition {
    Name("DeviceCrypto")

    Function("isAuthCheckAvailable") { ->
      return@Function isAuthCheckAvailable()
    }

    Function("generateKeyPair") { alias: String, o: Map<String, Any?> ->
      return@Function generateKeyPair(alias, o)
    }

    Function("removeKeyPair") { alias: String ->
      return@Function removeKeyStoreEntry(alias)
    }

    Function("aliases") {
      return@Function getAliases()
    }

    Function("getPublicKey") { alias: String ->
      return@Function getPublicKey(alias)
    }

    AsyncFunction("sign") { alias: String, data: String, o: Map<String, Any?>, promise: Promise ->
      return@AsyncFunction sign(alias, data, o, promise)
    }

    Function("verify") { alias: String, data: String, signature: String, o: Map<String, Any?> ->
      return@Function verify(alias, data, signature, o)
    }

    AsyncFunction("encrypt") { alias: String, data: String, o: Map<String, Any?>, promise: Promise ->
      return@AsyncFunction encrypt(alias, data, o, promise)
    }

    AsyncFunction("decrypt") { alias: String, data: String, o: Map<String, Any?>, promise: Promise ->
      return@AsyncFunction decrypt(alias, data, o, promise)
    }
  }
}
