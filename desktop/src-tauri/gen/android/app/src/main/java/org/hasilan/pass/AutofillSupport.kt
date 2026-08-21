package org.hasilan.pass

import android.app.assist.AssistStructure
import android.os.Build
import android.text.InputType
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import com.fasterxml.jackson.databind.ObjectMapper

private val credentialJson = ObjectMapper()

/** JNI entry points backed by the already-running shared Rust DesktopClient. */
internal object AutofillNative {
  init {
    // This is the `name` declared in desktop/src-tauri/Cargo.toml. Tauri packages the
    // cdylib as libhasilan_desktop_lib.so for every Android ABI.
    System.loadLibrary("hasilan_desktop_lib")
  }

  @JvmStatic external fun unlock(key: ByteArray): Boolean
  @JvmStatic external fun unlockContext(): String?
  @JvmStatic external fun initialize(dataDir: String): Boolean
  @JvmStatic external fun candidates(origin: String): String?
  @JvmStatic external fun credentialPasswordCandidates(): String?
  @JvmStatic external fun credentialPasskeyCandidates(rpId: String): String?
  @JvmStatic external fun assertCredentialPasskey(itemId: String, credentialId: String, optionsJson: String): String?
  @JvmStatic external fun passkeyCreationTargets(rpId: String): String?
  @JvmStatic external fun createCredentialPasskey(itemId: String, optionsJson: String): String?
  @JvmStatic external fun lockNative()
  @JvmStatic external fun lockApp()
  @JvmStatic external fun saveLogin(origin: String, username: String?, password: String, name: String): Boolean
}

internal data class AutofillCandidate(
  val id: String,
  val name: String,
  val username: String?,
  val password: String?,
  val totp: String?,
)

internal data class PasskeyCandidate(
  val itemId: String,
  val credentialId: String,
  val rpId: String,
  val userName: String?,
  val displayName: String,
)

/** Extracts only fillable IDs and an untrusted identity from a system AssistStructure.
 *
 * `webOrigin` and `packageName` are never used to retrieve a vault entry until
 * [AutofillTrust] has tied them to a signed browser or a Digital Asset Links statement.
 */
@androidx.annotation.RequiresApi(Build.VERSION_CODES.O)
internal data class AutofillTarget(
  val webOrigin: String?,
  val packageName: String?,
  val usernameId: AutofillId?,
  val passwordId: AutofillId?,
  val otpId: AutofillId?,
) {
  val ids: List<AutofillId>
    get() = listOfNotNull(usernameId, passwordId, otpId)

  val saveIds: List<AutofillId>
    get() = listOfNotNull(usernameId, passwordId)

  companion object {
    fun from(structure: AssistStructure?): AutofillTarget? {
      if (structure == null) return null
      var usernameId: AutofillId? = null
      var passwordId: AutofillId? = null
      var otpId: AutofillId? = null
      var domain: String? = null

      fun visit(node: AssistStructure.ViewNode) {
        val id = node.autofillId
        val hints = node.autofillHints.orEmpty().map { it.lowercase() }
        val variation = node.inputType and InputType.TYPE_MASK_VARIATION
        val password = hints.any { it.contains("password") || it.contains("new-password") } ||
          variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
          variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD ||
          variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD
        val username = hints.any {
          it.contains("username") || it.contains("email") || it.contains("login")
        } || variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
        val otp = hints.any {
          it.contains("one-time-code") || it.contains("one_time_code") ||
            it.contains("otp") || it.contains("verification")
        }
        if (id != null) {
          if (otp && otpId == null) otpId = id
          if (!otp && password && passwordId == null) passwordId = id
          if (!otp && !password && username && usernameId == null) usernameId = id
        }
        if (domain == null && !node.webDomain.isNullOrBlank()) domain = node.webDomain
        for (index in 0 until node.childCount) visit(node.getChildAt(index))
      }

      for (index in 0 until structure.windowNodeCount) visit(structure.getWindowNodeAt(index).rootViewNode)
      val webOrigin = domain?.let { CredentialOrigin.canonicalHttpsOrigin("https://$it") }
      val componentPackage = structure.activityComponent?.packageName
        ?.takeIf { it.length in 1..255 && it.matches(Regex("[A-Za-z0-9_.]+")) }
      val ids = listOfNotNull(usernameId, passwordId, otpId)
      if (ids.isEmpty()) return null
      if (webOrigin == null && componentPackage == null) return null
      return AutofillTarget(webOrigin, componentPackage, usernameId, passwordId, otpId)
    }

    fun values(structure: AssistStructure?): Pair<String?, String?>? {
      if (structure == null) return null
      var username: String? = null
      var password: String? = null

      fun text(value: AutofillValue?): String? =
        if (value?.isText == true) value.textValue.toString().takeIf { it.length <= 16_384 } else null

      fun visit(node: AssistStructure.ViewNode) {
        val hints = node.autofillHints.orEmpty().map { it.lowercase() }
        val variation = node.inputType and InputType.TYPE_MASK_VARIATION
        val value = text(node.autofillValue)
        val passwordField = hints.any { it.contains("password") } ||
          variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
          variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD
        val usernameField = hints.any { it.contains("username") || it.contains("email") } ||
          variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
        if (value != null) {
          if (passwordField && password == null) password = value
          if (!passwordField && usernameField && username == null) username = value
        }
        for (index in 0 until node.childCount) visit(node.getChildAt(index))
      }

      for (index in 0 until structure.windowNodeCount) visit(structure.getWindowNodeAt(index).rootViewNode)
      return password?.let { username to it }
    }
  }
}

internal fun parseCandidates(value: String?): List<AutofillCandidate> {
  if (value == null || value.length > 1_000_000) return emptyList()
  return try {
    val array = credentialJson.readTree(value)
    if (!array.isArray) return emptyList()
    buildList {
      array.forEach { item ->
        if (!item.isObject) return@forEach
        val id = item.path("id").asText("")
        val name = item.path("name").asText("")
        if (id.isBlank() || name.isBlank()) return@forEach
        add(
          AutofillCandidate(
            id = id,
            name = name,
            username = item.path("username").asText("").takeIf { it.isNotBlank() },
            password = item.path("password").asText("").takeIf { it.isNotBlank() },
            totp = item.path("totp").asText("").takeIf { it.isNotBlank() },
          ),
        )
      }
    }
  } catch (_: Exception) {
    emptyList()
  }
}

internal fun parsePasskeyCandidates(value: String?): List<PasskeyCandidate> {
  if (value == null || value.length > 1_000_000) return emptyList()
  return try {
    val array = credentialJson.readTree(value)
    if (!array.isArray) return emptyList()
    buildList {
      array.forEach { item ->
        if (!item.isObject) return@forEach
        val itemId = item.path("itemId").asText("")
        val credentialId = item.path("credentialId").asText("")
        val rpId = item.path("rpId").asText("")
        val displayName = item.path("displayName").asText("")
        if (itemId.isBlank() || credentialId.isBlank() || rpId.isBlank() || displayName.isBlank()) return@forEach
        add(
          PasskeyCandidate(
            itemId = itemId,
            credentialId = credentialId,
            rpId = rpId,
            userName = item.path("userName").asText("").takeIf { it.isNotBlank() },
            displayName = displayName,
          ),
        )
      }
    }
  } catch (_: Exception) {
    emptyList()
  }
}
