package expo.modules.securesigning

import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.security.KeyPairGenerator
import java.security.KeyStore
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import expo.modules.kotlin.Promise
import java.security.Signature
import android.widget.Toast
import android.content.Context
import java.security.KeyFactory

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

class SecureSigningModule : Module() {
  private fun isAuthCheckAvailable(): AuthCheckResult {
    val biometricManager = BiometricManager.from(appContext.reactContext as Context)
    return when (biometricManager.canAuthenticate(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)) {
      BiometricManager.BIOMETRIC_SUCCESS -> AuthCheckResult.AVAILABLE
      BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> AuthCheckResult.NO_HARDWARE
      BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> AuthCheckResult.UNAVAILABLE
      else -> AuthCheckResult.UNAVAILABLE
    }
  }

  private fun isKeyStoreAvailable(): Boolean {
    val pm = appContext.reactContext?.packageManager ?: return false
    val appAttestKeystore = pm.hasSystemFeature(PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY)
    val hardwareKeystore = pm.hasSystemFeature(PackageManager.FEATURE_HARDWARE_KEYSTORE)
    return appAttestKeystore && hardwareKeystore
  }

  private fun isStrongBoxAvailable(): Boolean {
    val pm = appContext.reactContext?.packageManager ?: return false
    val strongboxKeystore = pm.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    return strongboxKeystore
  }

  private fun getAliases() = KeyStore.getInstance("AndroidKeyStore").apply {
    load(null)
  }.aliases().toList()

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

  private fun retrievePublicKey(ks: KeyStore.Entry?): String? {
    if (ks !is KeyStore.PrivateKeyEntry) return null
    
    val publicKeyBytes: ByteArray = ks.certificate?.publicKey?.encoded ?: return null
    return Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP)
  }

  private fun removeKeyStoreEntry(alias: String): Boolean {
    val ks = KeyStore.getInstance("AndroidKeyStore").apply {
      load(null)
    }
    if (ks.getEntry(alias, null) == null) return false

    ks.deleteEntry(alias)
    return true
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
            AuthMethod.PASSCODE -> BiometricManager.Authenticators.DEVICE_CREDENTIAL
            AuthMethod.PASSCODE_OR_BIOMETRIC -> BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
          }
        )
        .build()

      biometricPrompt.authenticate(promptInfo)
    }
  }

  override fun definition() = ModuleDefinition {
    Name("SecureSigning")

    Function("isAuthCheckAvailable") { ->
      return@Function isAuthCheckAvailable()
    }

    Function("generateKeyPair") { alias: String, o: Map<String, Any?> ->
      val reqAuth = o["reqAuth"] as Boolean
      if (reqAuth && isAuthCheckAvailable() != AuthCheckResult.AVAILABLE) {
        throw Exception("NO_AUTH_AVAILABLE")
      }
      if (!isKeyStoreAvailable()) {
        return@Function GenerateKeyPairResult.NOT_AVAILABLE
      }
      if (getKeyStoreEntry(alias) != null) {
        return@Function GenerateKeyPairResult.KEY_PAIR_ALREADY_EXISTS
      }

      val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_EC,
        "AndroidKeyStore"
      )

      val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder(
        alias,
        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
      ).run {
        setDigests(KeyProperties.DIGEST_SHA256)
        setIsStrongBoxBacked(isStrongBoxAvailable())
        setUserAuthenticationRequired(reqAuth)
        if (reqAuth) {
          setUserAuthenticationParameters(
            30, // 30 seconds
            KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
          )
        }
        build()
      }
      kpg.initialize(parameterSpec)
      kpg.generateKeyPair()

      return@Function GenerateKeyPairResult.KEY_PAIR_GENERATED
    }

    Function("removeKeyPair") { alias: String ->
      return@Function removeKeyStoreEntry(alias)
    }

    Function("aliases") {
      return@Function getAliases()
    }

    Function("getPublicKey") { alias: String ->
      val entry = getKeyStoreEntry(alias)
      return@Function retrievePublicKey(entry)
    }

    AsyncFunction("sign") { alias: String,
      data: String,
      o:  Map<String, Any?>,
      promise: Promise ->
      val entry = getKeyStoreEntry(alias)
      if (entry !is KeyStore.PrivateKeyEntry) {
        promise.resolve(null)
        return@AsyncFunction
      }

      val reqAuth = isKeyStoreRequireAuthentication(entry);

      val title = o["title"] as String
      val subtitle = o["subtitle"] as String
      val authMethod = o["authMethod"] as String

      if (!reqAuth) {
        val signature: ByteArray = Signature.getInstance("SHA256withECDSA").apply {
          initSign(entry.privateKey)
          update(data.toByteArray(Charsets.UTF_8))
        }.sign()
        promise.resolve(Base64.encodeToString(signature, Base64.NO_WRAP))
        return@AsyncFunction
      } else {
        showAuthPrompt(
          onSuccess = {
            val signature: ByteArray = Signature.getInstance("SHA256withECDSA").apply {
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
          authMethod = when (authMethod) {
            "PASSCODE" -> AuthMethod.PASSCODE
            "PASSCODE_OR_BIOMETRIC" -> AuthMethod.PASSCODE_OR_BIOMETRIC
            else -> AuthMethod.PASSCODE_OR_BIOMETRIC
          }
        )
      }
    }

    Function("verify") { alias: String, data: String, signature: String ->
      val entry = getKeyStoreEntry(alias)
      if (entry !is KeyStore.PrivateKeyEntry) return@Function null
      
      val valid: Boolean = Signature.getInstance("SHA256withECDSA").apply {
        initVerify(entry.certificate)
        update(data.toByteArray(Charsets.UTF_8))
      }.verify(Base64.decode(signature, Base64.NO_WRAP))
      return@Function true
    }
  }
}
