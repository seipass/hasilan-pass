package org.hasilan.pass

import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.provider.PendingIntentHandler
import androidx.fragment.app.FragmentActivity
import org.json.JSONArray
import org.json.JSONObject
import kotlin.concurrent.thread

/**
 * Explicit, biometric-gated Credential Manager creation flow.
 *
 * Android passes the original WebAuthn request to this activity. The user must choose an
 * existing matching vault login before the shared Rust core generates and persists the key.
 */
class CredentialProviderCreateActivity : FragmentActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
    if (!AutofillNative.initialize(applicationInfo.dataDir)) {
      finish()
      return
    }
    val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
    val calling = request?.callingRequest as? CreatePublicKeyCredentialRequest
    val rpId = calling?.requestJson?.let(::rpIdFromCreationJson)
    if (request == null || calling == null || rpId == null) {
      finish()
      return
    }
    val context = AutofillNative.unlockContext() ?: run {
      finish()
      return
    }
    BiometricVault.unwrap(this, context, { key ->
      val unlocked = AutofillNative.unlock(key)
      key.fill(0)
      if (!unlocked) {
        finish()
        return@unwrap
      }
      thread(name = "hasilan-passkey-origin") {
        val origin = CredentialOrigin.trustedPasskeyOrigin(this, request.callingAppInfo, rpId)
        runOnUiThread {
          if (origin == null) {
            lockAndFinish()
          } else {
            chooseTarget(calling, rpId, origin)
          }
        }
      }
    }, { finish() })
  }

  private fun chooseTarget(
    calling: CreatePublicKeyCredentialRequest,
    rpId: String,
    origin: String,
  ) {
    val targets = parseCandidates(AutofillNative.passkeyCreationTargets(rpId))
    if (targets.isEmpty()) {
      AutofillNative.lockNative()
      finish()
      return
    }
    val labels = targets.map { target ->
      target.username?.let { "$it — ${target.name}" } ?: target.name
    }.toTypedArray()
    AlertDialog.Builder(this)
      .setTitle(R.string.passkey_create_title)
      .setMessage(R.string.passkey_create_message)
      .setNegativeButton(R.string.cancel) { _, _ -> lockAndFinish() }
      .setOnCancelListener { lockAndFinish() }
      .setItems(labels) { _, position ->
        create(calling, origin, targets[position].id)
      }
      .show()
  }

  private fun create(
    calling: CreatePublicKeyCredentialRequest,
    origin: String,
    itemId: String,
  ) {
    val options = withOrigin(calling.requestJson, origin) ?: run {
      lockAndFinish()
      return
    }
    val created = AutofillNative.createCredentialPasskey(itemId, options)?.let(::JSONObject) ?: run {
      lockAndFinish()
      return
    }
    val response = JSONObject().apply {
      put("id", created.getString("credentialId"))
      put("rawId", created.getString("credentialId"))
      put("type", "public-key")
      put("response", JSONObject().apply {
        put("clientDataJSON", created.getString("clientDataJson"))
        put("attestationObject", created.getString("attestationObject"))
        put("transports", JSONArray(created.getJSONArray("transports").toString()))
      })
      put("clientExtensionResults", JSONObject())
    }
    val result = Intent()
    PendingIntentHandler.setCreateCredentialResponse(
      result,
      CreatePublicKeyCredentialResponse(response.toString()),
    )
    AutofillNative.lockNative()
    setResult(RESULT_OK, result)
    finish()
  }

  private fun lockAndFinish() {
    AutofillNative.lockNative()
    finish()
  }

  private fun rpIdFromCreationJson(value: String): String? = try {
    JSONObject(value).optJSONObject("rp")?.optString("id")
      ?.takeIf { it.isNotBlank() && it.length <= 253 }
  } catch (_: Exception) {
    null
  }

  private fun withOrigin(value: String, origin: String): String? = try {
    JSONObject(value).apply { put("origin", origin) }.toString()
  } catch (_: Exception) {
    null
  }
}
