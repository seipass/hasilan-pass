package org.hasilan.pass

import android.app.Activity
import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.OpenableColumns
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.camera.core.ExperimentalGetImage
import androidx.activity.result.ActivityResult
import androidx.core.content.ContextCompat
import androidx.credentials.CreateCredentialResponse
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.CredentialManagerCallback
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialException
import app.tauri.annotation.Command
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.Permission
import app.tauri.annotation.PermissionCallback
import app.tauri.annotation.TauriPlugin
import app.tauri.PermissionState
import app.tauri.plugin.Invoke
import app.tauri.plugin.Plugin
import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.security.KeyStore
import java.security.ProviderException
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

@InvokeArg
class SecretKeyArgs {
  lateinit var key: String
}

@InvokeArg
class SecretValueArgs {
  lateinit var key: String
  lateinit var value: String
}

@InvokeArg
class ClipboardArgs {
  lateinit var value: String
  var clearAfterSeconds: Long = 30
}

@InvokeArg
class ClipboardPolicyArgs {
  var clearAfterSeconds: Long = 30
}

@InvokeArg
class BiometricKeyArgs {
  lateinit var key: String
}

@InvokeArg
class AccountPasskeyOptionsArgs {
  lateinit var optionsJson: String
}

@InvokeArg
class AttachmentDownloadArgs {
  lateinit var fileName: String
}

@InvokeArg
class AttachmentCommitArgs {
  lateinit var handle: String
  lateinit var path: String
}

@InvokeArg
class AttachmentDiscardArgs {
  lateinit var path: String
}

@InvokeArg
class AttachmentDownloadDiscardArgs {
  lateinit var handle: String
  lateinit var path: String
}

/** Keeps a Storage Access Framework display name from becoming an app-private path traversal. */
internal fun safeAttachmentFileName(value: String?): String? = value
  ?.replace('/', '_')
  ?.replace('\\', '_')
  ?.replace('\u0000', '_')
  ?.trim()
  ?.take(180)
  ?.takeIf { it.isNotEmpty() && it != "." && it != ".." }

/**
 * Android Keystore envelope helpers. Vault encryption remains in Rust; this only wraps data that
 * the core explicitly delegates to the operating system (refresh/device material and the
 * user-authentication-bound biometric unlock key).
 */
internal object AndroidKeystore {
  private const val ANDROID_KEYSTORE = "AndroidKeyStore"
  private const val STORAGE_KEY_ALIAS = "hasilan.pass.storage.v1"
  private const val BIOMETRIC_KEY_ALIAS = "hasilan.pass.biometric.v1"
  private const val GCM_IV_BYTES = 12
  private const val GCM_TAG_BITS = 128

  private fun key(alias: String, requireAuth: Boolean): SecretKey {
    val store = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    val existing = store.getKey(alias, null) as? SecretKey
    if (existing != null) return existing
    // StrongBox is preferred where the device provides it, but never required: rejecting a
    // capable non-StrongBox device would weaken availability without changing vault cryptography.
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      try {
        return generateKey(alias, requireAuth, strongBox = true)
      } catch (_: ProviderException) {
        // The hardware does not expose StrongBox or has no slot available; use Android Keystore.
      } catch (_: Exception) {
        // Some vendor providers report unsupported StrongBox as InvalidAlgorithmParameterException.
      }
    }
    return generateKey(alias, requireAuth, strongBox = false)
  }

  private fun generateKey(alias: String, requireAuth: Boolean, strongBox: Boolean): SecretKey {
    val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
    val spec = KeyGenParameterSpec.Builder(
      alias,
      KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
    )
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setRandomizedEncryptionRequired(true)
      .apply {
        if (requireAuth) {
          setUserAuthenticationRequired(true)
          if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            setUserAuthenticationParameters(
              0,
              KeyProperties.AUTH_BIOMETRIC_STRONG,
            )
          }
          setInvalidatedByBiometricEnrollment(true)
        }
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          setIsStrongBoxBacked(true)
        }
      }
      .build()
    generator.init(spec)
    return generator.generateKey()
  }

  private fun keyInfo(alias: String): KeyInfo? {
    val secret = try {
      KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.getKey(alias, null) as? SecretKey
    } catch (_: Exception) {
      null
    } ?: return null
    return try {
      SecretKeyFactory.getInstance(secret.algorithm, ANDROID_KEYSTORE)
        .getKeySpec(secret, KeyInfo::class.java) as? KeyInfo
    } catch (_: Exception) {
      null
    }
  }

  /** Reports actual protection properties; absence means the lazily-created alias does not exist. */
  fun protectionStatus(context: Context): Map<String, Boolean> {
    val storage = keyInfo(STORAGE_KEY_ALIAS)
    val biometric = keyInfo(BIOMETRIC_KEY_ALIAS)
    return mapOf(
      "storageHardwareBacked" to (storage?.isInsideSecureHardware == true),
      "biometricHardwareBacked" to (biometric?.isInsideSecureHardware == true),
      "storageStrongBoxBacked" to isStrongBoxBacked(storage),
      "biometricStrongBoxBacked" to isStrongBoxBacked(biometric),
      "strongBoxAvailable" to (
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
          context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
      ),
    )
  }

  private fun isStrongBoxBacked(info: KeyInfo?): Boolean =
    Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
      info?.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX

  private fun pack(iv: ByteArray, ciphertext: ByteArray): String {
    val bytes = ByteArray(1 + iv.size + ciphertext.size)
    bytes[0] = iv.size.toByte()
    iv.copyInto(bytes, 1)
    ciphertext.copyInto(bytes, 1 + iv.size)
    return Base64.encodeToString(bytes, Base64.NO_WRAP)
  }

  private fun unpack(value: String): Pair<ByteArray, ByteArray>? {
    val bytes = try {
      Base64.decode(value, Base64.NO_WRAP)
    } catch (_: IllegalArgumentException) {
      return null
    }
    if (bytes.isEmpty()) return null
    val ivLength = bytes[0].toInt() and 0xff
    if (ivLength != GCM_IV_BYTES || bytes.size <= 1 + ivLength) return null
    return bytes.copyOfRange(1, 1 + ivLength) to bytes.copyOfRange(1 + ivLength, bytes.size)
  }

  fun encryptStorage(plaintext: ByteArray): String {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, key(STORAGE_KEY_ALIAS, false))
    return pack(cipher.iv, cipher.doFinal(plaintext))
  }

  fun decryptStorage(value: String): ByteArray? {
    val (iv, ciphertext) = unpack(value) ?: return null
    return try {
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(
        Cipher.DECRYPT_MODE,
        key(STORAGE_KEY_ALIAS, false),
        GCMParameterSpec(GCM_TAG_BITS, iv),
      )
      cipher.doFinal(ciphertext)
    } catch (_: Exception) {
      null
    }
  }

  fun biometricEncryptCipher(): Cipher {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, key(BIOMETRIC_KEY_ALIAS, true))
    return cipher
  }

  fun biometricDecryptCipher(value: String): Cipher? {
    val (iv, _) = unpack(value) ?: return null
    return try {
      Cipher.getInstance("AES/GCM/NoPadding").apply {
        init(
          Cipher.DECRYPT_MODE,
          key(BIOMETRIC_KEY_ALIAS, true),
          GCMParameterSpec(GCM_TAG_BITS, iv),
        )
      }
    } catch (_: Exception) {
      null
    }
  }

  fun biometricPack(cipher: Cipher, plaintext: ByteArray): String = pack(cipher.iv, cipher.doFinal(plaintext))

  fun biometricDecrypt(cipher: Cipher, value: String): ByteArray? {
    val (_, ciphertext) = unpack(value) ?: return null
    return try {
      cipher.doFinal(ciphertext)
    } catch (_: Exception) {
      null
    }
  }

  fun deleteBiometricKey() {
    try {
      KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
        if (containsAlias(BIOMETRIC_KEY_ALIAS)) deleteEntry(BIOMETRIC_KEY_ALIAS)
      }
    } catch (_: Exception) {
      // There is no recoverable action for a missing / invalidated biometric alias.
    }
  }
}

/** The only persisted biometric material is an Android Keystore ciphertext of the Rust user key. */
internal object BiometricVault {
  private const val PREFS = "hasilan.pass.android.security"
  private const val BIOMETRIC_ENVELOPE = "biometric-user-key"

  private fun preferences(context: Context) =
    context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

  fun hasEnvelope(context: Context): Boolean = preferences(context).contains(BIOMETRIC_ENVELOPE)

  fun isAvailable(context: Context): Boolean =
    BiometricManager.from(context).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
      BiometricManager.BIOMETRIC_SUCCESS

  fun clear(context: Context) {
    preferences(context).edit().remove(BIOMETRIC_ENVELOPE).apply()
    AndroidKeystore.deleteBiometricKey()
  }

  private fun prompt(activity: Activity, cryptoObject: BiometricPrompt.CryptoObject, onSuccess: (Cipher) -> Unit, onError: () -> Unit) {
    val prompt = BiometricPrompt(
      activity as androidx.fragment.app.FragmentActivity,
      ContextCompat.getMainExecutor(activity),
      object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
          val cipher = result.cryptoObject?.cipher
          if (cipher == null) onError() else onSuccess(cipher)
        }

        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) = onError()
        override fun onAuthenticationFailed() = Unit
      },
    )
    prompt.authenticate(
      BiometricPrompt.PromptInfo.Builder()
        .setTitle(activity.getString(R.string.biometric_title))
        .setSubtitle(activity.getString(R.string.biometric_subtitle))
        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        .build(),
      cryptoObject,
    )
  }

  fun wrap(activity: Activity, userKey: ByteArray, onSuccess: () -> Unit, onError: () -> Unit) {
    if (!isAvailable(activity)) {
      onError()
      return
    }
    val cipher = try {
      AndroidKeystore.biometricEncryptCipher()
    } catch (_: Exception) {
      onError()
      return
    }
    prompt(activity, BiometricPrompt.CryptoObject(cipher), { authenticatedCipher ->
      try {
        val encoded = AndroidKeystore.biometricPack(authenticatedCipher, userKey)
        preferences(activity).edit().putString(BIOMETRIC_ENVELOPE, encoded).commit()
        onSuccess()
      } catch (_: Exception) {
        onError()
      }
    }, onError)
  }

  fun unwrap(activity: Activity, onSuccess: (ByteArray) -> Unit, onError: () -> Unit) {
    val envelope = preferences(activity).getString(BIOMETRIC_ENVELOPE, null)
    if (envelope == null || !isAvailable(activity)) {
      onError()
      return
    }
    val cipher = AndroidKeystore.biometricDecryptCipher(envelope)
    if (cipher == null) {
      clear(activity)
      onError()
      return
    }
    prompt(activity, BiometricPrompt.CryptoObject(cipher), { authenticatedCipher ->
      val key = AndroidKeystore.biometricDecrypt(authenticatedCipher, envelope)
      if (key == null) {
        clear(activity)
        onError()
      } else {
        onSuccess(key)
      }
    }, onError)
  }
}

@ExperimentalGetImage
@TauriPlugin(permissions = [Permission(strings = [Manifest.permission.CAMERA], alias = "camera")])
class AndroidSecurityPlugin(private val activity: Activity) : Plugin(activity) {
  companion object {
    private const val CLIPBOARD_CLEAR_SECONDS = "clipboard-clear-seconds"
    private const val DEFAULT_CLIPBOARD_CLEAR_SECONDS = 30L
    private const val ATTACHMENT_STAGE_DIRECTORY = "attachment-staging"
    private const val ATTACHMENT_COPY_BUFFER_BYTES = 32 * 1024
    // Attachments are encrypted by Rust in bounded chunks. Bound a hostile content provider so it
    // cannot consume all of an Android device's private cache before Rust gets control.
    private const val MAX_ATTACHMENT_BYTES = 1024L * 1024L * 1024L
  }
  private val preferences = activity.getSharedPreferences("hasilan.pass.android.security", Context.MODE_PRIVATE)
  private val clipboard = activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
  private val handler = Handler(Looper.getMainLooper())
  private val pendingAttachmentDestinations = ConcurrentHashMap<String, Uri>()

  init {
    // A process death cannot leave a reusable decrypted attachment behind. The directory is
    // private and contains only transfer files created by this plugin.
    attachmentStageDirectory().listFiles()?.forEach { discardStagedFile(it.absolutePath) }
  }

  @Command
  fun getSecret(invoke: Invoke) {
    val key = invoke.parseArgs(SecretKeyArgs::class.java).key
    val encoded = preferences.getString("secret:$key", null)
    val plaintext = encoded?.let(AndroidKeystore::decryptStorage)
    if (encoded != null && plaintext == null) preferences.edit().remove("secret:$key").apply()
    val value = plaintext?.let { Base64.encodeToString(it, Base64.NO_WRAP) }
    plaintext?.fill(0)
    invoke.resolveObject(mapOf("value" to value))
  }

  @Command
  fun setSecret(invoke: Invoke) {
    val args = invoke.parseArgs(SecretValueArgs::class.java)
    val value = try {
      Base64.decode(args.value, Base64.NO_WRAP)
    } catch (_: IllegalArgumentException) {
      invoke.reject("Invalid secure value")
      return
    }
    try {
      val encrypted = AndroidKeystore.encryptStorage(value)
      if (preferences.edit().putString("secret:${args.key}", encrypted).commit()) invoke.resolve()
      else invoke.reject("Secure storage is unavailable")
    } catch (_: Exception) {
      invoke.reject("Secure storage is unavailable")
    } finally {
      value.fill(0)
    }
  }

  @Command
  fun deleteSecret(invoke: Invoke) {
    val key = invoke.parseArgs(SecretKeyArgs::class.java).key
    preferences.edit().remove("secret:$key").apply()
    invoke.resolve()
  }

  @Command
  fun copySecret(invoke: Invoke) {
    val args = invoke.parseArgs(ClipboardArgs::class.java)
    clipboard.setPrimaryClip(ClipData.newPlainText("Hasilan Pass", args.value))
    val clearAfterSeconds = preferences
      .getLong(CLIPBOARD_CLEAR_SECONDS, DEFAULT_CLIPBOARD_CLEAR_SECONDS)
      .coerceIn(0, 120)
    if (clearAfterSeconds == 0L) {
      invoke.resolve()
      return
    }
    val expected = args.value
    handler.postDelayed({
      val current = clipboard.primaryClip?.getItemAt(0)?.text?.toString()
      if (current == expected) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) clipboard.clearPrimaryClip()
        else clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
      }
    }, clearAfterSeconds * 1_000)
    invoke.resolve()
  }

  @Command
  fun clipboardPolicy(invoke: Invoke) {
    invoke.resolveObject(
      mapOf(
        "clearAfterSeconds" to preferences
          .getLong(CLIPBOARD_CLEAR_SECONDS, DEFAULT_CLIPBOARD_CLEAR_SECONDS)
          .coerceIn(0, 120),
      ),
    )
  }

  @Command
  fun setClipboardPolicy(invoke: Invoke) {
    val seconds = invoke.parseArgs(ClipboardPolicyArgs::class.java).clearAfterSeconds.coerceIn(0, 120)
    if (preferences.edit().putLong(CLIPBOARD_CLEAR_SECONDS, seconds).commit()) invoke.resolveObject(
      mapOf("clearAfterSeconds" to seconds),
    ) else invoke.reject("Clipboard policy could not be saved")
  }

  @Command
  fun biometricStatus(invoke: Invoke) {
    invoke.resolveObject(
      mapOf(
        "enabled" to BiometricVault.hasEnvelope(activity),
        "available" to BiometricVault.isAvailable(activity),
      ) + AndroidKeystore.protectionStatus(activity),
    )
  }

  @Command
  fun enableBiometricUnlock(invoke: Invoke) {
    val args = invoke.parseArgs(BiometricKeyArgs::class.java)
    val key = try {
      Base64.decode(args.key, Base64.NO_WRAP)
    } catch (_: IllegalArgumentException) {
      invoke.reject("Invalid biometric key")
      return
    }
    BiometricVault.wrap(activity, key, {
      key.fill(0)
      invoke.resolveObject(mapOf("enabled" to true, "available" to true))
    }, {
      key.fill(0)
      invoke.reject("Biometric unlock was not enabled")
    })
  }

  @Command
  fun disableBiometricUnlock(invoke: Invoke) {
    BiometricVault.clear(activity)
    invoke.resolveObject(mapOf("enabled" to false, "available" to BiometricVault.isAvailable(activity)))
  }

  @Command
  fun openAutofillSettings(invoke: Invoke) {
    val intent = Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).apply {
      data = Uri.parse("package:${activity.packageName}")
    }
    try {
      activity.startActivity(intent)
      invoke.resolve()
    } catch (_: Exception) {
      invoke.reject("Android autofill settings are unavailable")
    }
  }

  @Command
  fun openCredentialProviderSettings(invoke: Invoke) {
    // Android 14+ shows this app's provider setting when the CredentialProviderService is present.
    // Older releases only support AutofillService and are routed there by the app UI.
    try {
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
        val manager = CredentialManager.create(activity)
        activity.startIntentSender(manager.createSettingsPendingIntent().intentSender, null, 0, 0, 0)
      } else {
        activity.startActivity(Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE))
      }
      invoke.resolve()
    } catch (_: Exception) {
      invoke.reject("Android credential settings are unavailable")
    }
  }

  /**
   * Creates an account passkey through Android Credential Manager. The server challenge stays
   * opaque here; Android supplies the calling APK-bound client-data origin from this installed
   * package and its signing certificate.
   */
  @Command
  fun createAccountPasskey(invoke: Invoke) {
    val requestJson = accountPasskeyRequestJson(invoke) ?: return
    val request = try {
      CreatePublicKeyCredentialRequest(requestJson)
    } catch (_: Exception) {
      invoke.reject("The account passkey challenge is invalid")
      return
    }
    CredentialManager.create(activity).createCredentialAsync(
      activity,
      request,
      android.os.CancellationSignal(),
      ContextCompat.getMainExecutor(activity),
      object : CredentialManagerCallback<CreateCredentialResponse, CreateCredentialException> {
        override fun onResult(result: CreateCredentialResponse) {
          val credential = result as? CreatePublicKeyCredentialResponse
          if (credential == null) {
            invoke.reject("Android did not return an account passkey")
            return
          }
          invoke.resolveObject(mapOf("credential" to credential.registrationResponseJson))
        }

        override fun onError(e: CreateCredentialException) {
          invoke.reject("Account passkey creation was cancelled or unavailable")
        }
      },
    )
  }

  /** Obtains an account-passkey assertion through the system Credential Manager selector. */
  @Command
  fun getAccountPasskey(invoke: Invoke) {
    val requestJson = accountPasskeyRequestJson(invoke) ?: return
    val option = try {
      GetPublicKeyCredentialOption(requestJson)
    } catch (_: Exception) {
      invoke.reject("The account passkey challenge is invalid")
      return
    }
    val request = GetCredentialRequest(listOf(option))
    CredentialManager.create(activity).getCredentialAsync(
      activity,
      request,
      android.os.CancellationSignal(),
      ContextCompat.getMainExecutor(activity),
      object : CredentialManagerCallback<GetCredentialResponse, GetCredentialException> {
        override fun onResult(result: GetCredentialResponse) {
          val credential = result.credential as? PublicKeyCredential
          if (credential == null) {
            invoke.reject("Android did not return an account passkey")
            return
          }
          invoke.resolveObject(mapOf("credential" to credential.authenticationResponseJson))
        }

        override fun onError(e: GetCredentialException) {
          invoke.reject("Account passkey authentication was cancelled or unavailable")
        }
      },
    )
  }

  /**
   * Invokes Android's Storage Access Framework and copies the user-selected file into private
   * cache. Rust receives only this private path and performs all attachment encryption, metadata
   * generation, chunking, and upload.
   */
  @Command
  fun pickAttachment(invoke: Invoke) {
    val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
      addCategory(Intent.CATEGORY_OPENABLE)
      type = "*/*"
      addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    try {
      startActivityForResult(invoke, intent, "attachmentPicked")
    } catch (_: Exception) {
      invoke.reject("Android file selection is unavailable")
    }
  }

  @ActivityCallback
  fun attachmentPicked(invoke: Invoke, result: ActivityResult) {
    val uri = result.data?.data
    if (result.resultCode != Activity.RESULT_OK || uri == null) {
      invoke.reject("Attachment selection was cancelled")
      return
    }
    val staged = try {
      copyAttachmentIntoPrivateCache(uri)
    } catch (_: AttachmentTooLarge) {
      invoke.reject("Attachments larger than 1 GiB are not supported on Android")
      return
    } catch (_: Exception) {
      invoke.reject("The selected attachment could not be read")
      return
    }
    invoke.resolveObject(mapOf("path" to staged.absolutePath))
  }

  /**
   * Prompts for a destination before Rust writes the authenticated plaintext into a private
   * temporary file. The opaque handle stays in Kotlin; JavaScript never receives the URI.
   */
  @Command
  fun prepareAttachmentDownload(invoke: Invoke) {
    val requestedName = try {
      invoke.parseArgs(AttachmentDownloadArgs::class.java).fileName
    } catch (_: Exception) {
      invoke.reject("The attachment destination is invalid")
      return
    }
    val fileName = safeAttachmentFileName(requestedName)
    if (fileName == null) {
      invoke.reject("The attachment destination is invalid")
      return
    }
    val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
      addCategory(Intent.CATEGORY_OPENABLE)
      type = "application/octet-stream"
      putExtra(Intent.EXTRA_TITLE, fileName)
      addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
    }
    try {
      startActivityForResult(invoke, intent, "attachmentDownloadDestination")
    } catch (_: Exception) {
      invoke.reject("Android file saving is unavailable")
    }
  }

  @ActivityCallback
  fun attachmentDownloadDestination(invoke: Invoke, result: ActivityResult) {
    val uri = result.data?.data
    if (result.resultCode != Activity.RESULT_OK || uri == null) {
      invoke.reject("Attachment save was cancelled")
      return
    }
    val staged = try {
      File.createTempFile("download-", ".partial", attachmentStageDirectory())
    } catch (_: Exception) {
      invoke.reject("A private attachment destination could not be created")
      return
    }
    val handle = UUID.randomUUID().toString()
    pendingAttachmentDestinations[handle] = uri
    invoke.resolveObject(mapOf("handle" to handle, "path" to staged.absolutePath))
  }

  /** Copies one Rust-authenticated private download to the user-selected SAF destination. */
  @Command
  fun commitAttachmentDownload(invoke: Invoke) {
    val args = try {
      invoke.parseArgs(AttachmentCommitArgs::class.java)
    } catch (_: Exception) {
      invoke.reject("The attachment destination is invalid")
      return
    }
    val uri = pendingAttachmentDestinations.remove(args.handle)
    val staged = stagedFile(args.path)
    if (uri == null || staged == null) {
      if (staged != null) discardStagedFile(staged.absolutePath)
      invoke.reject("The attachment destination is no longer available")
      return
    }
    val copied = try {
      val output = activity.contentResolver.openOutputStream(uri, "w")
      if (output == null) {
        false
      } else {
        output.use { destination ->
          staged.inputStream().use { input ->
            input.copyTo(destination, ATTACHMENT_COPY_BUFFER_BYTES)
            destination.flush()
          }
        }
        true
      }
    } catch (_: Exception) {
      false
    } finally {
      discardStagedFile(staged.absolutePath)
    }
    if (copied) {
      invoke.resolve()
    } else {
      try {
        activity.contentResolver.delete(uri, null, null)
      } catch (_: Exception) {
        // A provider may not support deletion; the user-selected provider owns any partial file.
      }
      invoke.reject("The selected attachment destination could not be written")
    }
  }

  /** Drops a pending SAF destination when Rust cannot complete the private download. */
  @Command
  fun discardAttachmentDownload(invoke: Invoke) {
    val args = try {
      invoke.parseArgs(AttachmentDownloadDiscardArgs::class.java)
    } catch (_: Exception) {
      invoke.reject("The attachment destination is invalid")
      return
    }
    pendingAttachmentDestinations.remove(args.handle)
    discardStagedFile(args.path)
    invoke.resolve()
  }

  /** Best-effort cleanup used on both successful and failed encrypted uploads/downloads. */
  @Command
  fun discardAttachmentStaging(invoke: Invoke) {
    val path = try {
      invoke.parseArgs(AttachmentDiscardArgs::class.java).path
    } catch (_: Exception) {
      invoke.reject("The private attachment file is invalid")
      return
    }
    discardStagedFile(path)
    invoke.resolve()
  }

  /** Opens the on-device ZXing QR reader. The raw value never leaves the app process. */
  @Command
  fun scanTotp(invoke: Invoke) {
    if (getPermissionState(Manifest.permission.CAMERA) == PermissionState.GRANTED) {
      startTotpScanner(invoke)
    } else {
      requestPermissionForAlias("camera", invoke, "cameraPermissionForTotp")
    }
  }

  @PermissionCallback
  fun cameraPermissionForTotp(invoke: Invoke) {
    if (getPermissionState(Manifest.permission.CAMERA) != PermissionState.GRANTED) {
      invoke.reject("Camera permission is required to scan a TOTP QR code")
      return
    }
    startTotpScanner(invoke)
  }

  /** Converts the existing browser-shaped WebAuthn wrapper into Credential Manager JSON. */
  private fun accountPasskeyRequestJson(invoke: Invoke): String? {
    val value = try {
      invoke.parseArgs(AccountPasskeyOptionsArgs::class.java).optionsJson
    } catch (_: Exception) {
      invoke.reject("The account passkey challenge is invalid")
      return null
    }
    if (value.isBlank() || value.length > 262_144) {
      invoke.reject("The account passkey challenge is invalid")
      return null
    }
    return AccountPasskeyJson.publicKeyOptions(value) ?: run {
      invoke.reject("The account passkey challenge is invalid")
      null
    }
  }

  private fun startTotpScanner(invoke: Invoke) {
    startActivityForResult(
      invoke,
      Intent(activity, QrScanActivity::class.java),
      "totpQrScanned",
    )
  }

  @ActivityCallback
  fun totpQrScanned(invoke: Invoke, result: ActivityResult) {
    val value = result.data?.getStringExtra(QrScanActivity.EXTRA_TOTP)
    if (result.resultCode == Activity.RESULT_OK && !value.isNullOrBlank()) {
      invoke.resolveObject(mapOf("value" to value))
    } else {
      invoke.reject("TOTP QR scanning was cancelled")
    }
  }

  private class AttachmentTooLarge : Exception()

  private fun attachmentStageDirectory(): File = File(activity.cacheDir, ATTACHMENT_STAGE_DIRECTORY).apply {
    if (!exists() && !mkdirs()) throw IllegalStateException("Attachment cache directory is unavailable")
  }

  private fun stagedFile(path: String): File? = try {
    val directory = attachmentStageDirectory().canonicalFile
    val file = File(path).canonicalFile
    if (file.parentFile == directory && file.isFile) file else null
  } catch (_: Exception) {
    null
  }

  private fun copyAttachmentIntoPrivateCache(uri: Uri): File {
    val name = safeAttachmentFileName(displayName(uri)) ?: "attachment.bin"
    val staged = File.createTempFile("import-", "-$name", attachmentStageDirectory())
    try {
      val input = activity.contentResolver.openInputStream(uri)
        ?: throw IllegalStateException("Attachment stream is unavailable")
      input.use { source ->
        FileOutputStream(staged).use { destination ->
          val buffer = ByteArray(ATTACHMENT_COPY_BUFFER_BYTES)
          var copied = 0L
          while (true) {
            val count = source.read(buffer)
            if (count < 0) break
            copied += count.toLong()
            if (copied > MAX_ATTACHMENT_BYTES) throw AttachmentTooLarge()
            destination.write(buffer, 0, count)
          }
          destination.flush()
        }
      }
      return staged
    } catch (error: Exception) {
      discardStagedFile(staged.absolutePath)
      throw error
    }
  }

  private fun displayName(uri: Uri): String? = try {
    activity.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
      val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
      if (index >= 0 && cursor.moveToFirst()) cursor.getString(index) else null
    }
  } catch (_: Exception) {
    null
  }

  /** Android/flash storage cannot promise physical erasure; overwrite is a best-effort guard. */
  private fun discardStagedFile(path: String) {
    val file = stagedFile(path) ?: return
    try {
      RandomAccessFile(file, "rw").use { stream ->
        val zeroes = ByteArray(ATTACHMENT_COPY_BUFFER_BYTES)
        var remaining = stream.length()
        stream.seek(0)
        while (remaining > 0) {
          val count = minOf(remaining, zeroes.size.toLong()).toInt()
          stream.write(zeroes, 0, count)
          remaining -= count.toLong()
        }
        stream.fd.sync()
      }
    } catch (_: Exception) {
      // Cache deletion still occurs below if overwrite is unsupported by the underlying provider.
    }
    try {
      file.delete()
    } catch (_: Exception) {
      // App-private cache is retried at next plugin initialization.
    }
  }
}
