package org.hasilan.pass

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Bundle
import android.view.WindowManager
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PasswordCredential
import androidx.credentials.PublicKeyCredential
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPasswordOption
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.PasswordCredentialEntry
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderGetCredentialRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import androidx.fragment.app.FragmentActivity
import org.json.JSONObject
import kotlin.concurrent.thread

/** Completes both Credential Manager unlock and a user-selected password / passkey operation. */
class CredentialProviderAuthActivity : FragmentActivity() {
  companion object {
    const val ACTION_UNLOCK = "org.hasilan.pass.credentials.UNLOCK"
    const val ACTION_PASSWORD = "org.hasilan.pass.credentials.PASSWORD"
    const val ACTION_PASSKEY = "org.hasilan.pass.credentials.PASSKEY"
    const val EXTRA_ITEM_ID = "org.hasilan.pass.credentials.ITEM_ID"
    const val EXTRA_CREDENTIAL_ID = "org.hasilan.pass.credentials.CREDENTIAL_ID"
    const val EXTRA_RP_ID = "org.hasilan.pass.credentials.RP_ID"
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
    if (!AutofillNative.initialize(applicationInfo.dataDir)) {
      finish()
      return
    }
    when (intent.action) {
      ACTION_UNLOCK -> unlockBeginRequest()
      ACTION_PASSWORD, ACTION_PASSKEY -> unlockSelection()
      else -> finish()
    }
  }

  private fun unlockBeginRequest() {
    val beginRequest = PendingIntentHandler.retrieveBeginGetCredentialRequest(intent)
    if (beginRequest == null) {
      startActivity(Intent(this, MainActivity::class.java))
      finish()
      return
    }
    BiometricVault.unwrap(this, { key ->
      val unlocked = AutofillNative.unlock(key)
      key.fill(0)
      if (!unlocked) {
        finish()
        return@unwrap
      }
      val response = beginResponse(beginRequest)
      AutofillNative.lockNative()
      if (response == null) {
        finish()
        return@unwrap
      }
      val result = Intent()
      PendingIntentHandler.setBeginGetCredentialResponse(result, response)
      setResult(RESULT_OK, result)
      finish()
    }, { finish() })
  }

  private fun beginResponse(request: BeginGetCredentialRequest): BeginGetCredentialResponse? {
    val entries = mutableListOf<androidx.credentials.provider.CredentialEntry>()
    request.beginGetCredentialOptions.forEach optionLoop@ { option ->
      when (option) {
        is BeginGetPasswordOption -> {
          parseCandidates(AutofillNative.credentialPasswordCandidates()).forEach candidateLoop@ { candidate ->
            val username = candidate.username ?: return@candidateLoop
            val pending = selectionPendingIntent(ACTION_PASSWORD, candidate.id, null, null)
            entries += PasswordCredentialEntry(
              this,
              username,
              pending,
              option,
              candidate.name,
              null,
              Icon.createWithResource(this, R.mipmap.ic_launcher),
              false,
            )
          }
        }
        is BeginGetPublicKeyCredentialOption -> {
          val rpId = rpIdFromGetJson(option.requestJson) ?: return@optionLoop
          parsePasskeyCandidates(AutofillNative.credentialPasskeyCandidates(rpId)).forEach { candidate ->
            val pending = selectionPendingIntent(
              ACTION_PASSKEY,
              candidate.itemId,
              candidate.credentialId,
              candidate.rpId,
            )
            entries += PublicKeyCredentialEntry(
              this,
              candidate.userName ?: candidate.displayName,
              pending,
              option,
              candidate.displayName,
              null,
              Icon.createWithResource(this, R.mipmap.ic_launcher),
              false,
              false,
            )
          }
        }
      }
    }
    return entries.takeIf { it.isNotEmpty() }?.let(::BeginGetCredentialResponse)
  }

  private fun selectionPendingIntent(
    action: String,
    itemId: String,
    credentialId: String?,
    rpId: String?,
  ): PendingIntent {
    val intent = Intent(this, CredentialProviderAuthActivity::class.java).apply {
      this.action = action
      putExtra(EXTRA_ITEM_ID, itemId)
      credentialId?.let { putExtra(EXTRA_CREDENTIAL_ID, it) }
      rpId?.let { putExtra(EXTRA_RP_ID, it) }
    }
    val requestCode = (action + itemId + credentialId.orEmpty()).hashCode()
    return PendingIntent.getActivity(
      this,
      requestCode,
      intent,
      PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )
  }

  private fun unlockSelection() {
    val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
    val itemId = intent.getStringExtra(EXTRA_ITEM_ID)
    if (request == null || itemId.isNullOrBlank()) {
      finish()
      return
    }
    BiometricVault.unwrap(this, { key ->
      val unlocked = AutofillNative.unlock(key)
      key.fill(0)
      if (!unlocked) {
        finish()
        return@unwrap
      }
      when (intent.action) {
        ACTION_PASSWORD -> completePassword(itemId)
        ACTION_PASSKEY -> completePasskey(request, itemId)
      }
    }, { finish() })
  }

  private fun completePassword(itemId: String) {
    val candidate = parseCandidates(AutofillNative.credentialPasswordCandidates())
      .firstOrNull { it.id == itemId && !it.username.isNullOrBlank() && !it.password.isNullOrBlank() }
    if (candidate == null) {
      AutofillNative.lockNative()
      finish()
      return
    }
    val result = Intent()
    PendingIntentHandler.setGetCredentialResponse(
      result,
      GetCredentialResponse(PasswordCredential(candidate.username!!, candidate.password!!)),
    )
    AutofillNative.lockNative()
    setResult(RESULT_OK, result)
    finish()
  }

  private fun completePasskey(request: ProviderGetCredentialRequest, itemId: String) {
    val option = request.credentialOptions.filterIsInstance<GetPublicKeyCredentialOption>().firstOrNull()
    val credentialId = intent.getStringExtra(EXTRA_CREDENTIAL_ID)
    val rpId = intent.getStringExtra(EXTRA_RP_ID)
    if (option == null || credentialId.isNullOrBlank() || rpId.isNullOrBlank()) {
      AutofillNative.lockNative()
      finish()
      return
    }
    thread(name = "hasilan-passkey-origin") {
      val origin = CredentialOrigin.trustedPasskeyOrigin(this, request.callingAppInfo, rpId)
      val options = origin?.let { passkeyOptions(option.requestJson, it) }
      val assertion = options?.let {
        AutofillNative.assertCredentialPasskey(itemId, credentialId, it)
      }
      runOnUiThread {
        completePasskeyResult(assertion)
      }
    }
  }

  private fun completePasskeyResult(assertion: String?) {
    val json = assertion?.let(::JSONObject) ?: run {
      AutofillNative.lockNative()
      finish()
      return
    }
    val response = JSONObject().apply {
      put("id", json.getString("credentialId"))
      put("rawId", json.getString("credentialId"))
      put("type", "public-key")
      put("response", JSONObject().apply {
        put("clientDataJSON", json.getString("clientDataJson"))
        put("authenticatorData", json.getString("authenticatorData"))
        put("signature", json.getString("signature"))
        if (!json.isNull("userHandle")) put("userHandle", json.getString("userHandle"))
      })
    }
    val result = Intent()
    PendingIntentHandler.setGetCredentialResponse(
      result,
      GetCredentialResponse(PublicKeyCredential(response.toString())),
    )
    AutofillNative.lockNative()
    setResult(RESULT_OK, result)
    finish()
  }

  private fun rpIdFromGetJson(value: String): String? = try {
    JSONObject(value).optString("rpId").takeIf { it.isNotBlank() && it.length <= 253 }
  } catch (_: Exception) {
    null
  }

  private fun passkeyOptions(value: String, origin: String): String? = try {
    JSONObject(value).apply { put("origin", origin) }.toString()
  } catch (_: Exception) {
    null
  }
}
