package org.hasilan.pass

import android.app.PendingIntent
import android.content.Intent
import android.os.CancellationSignal
import android.os.Build
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillManager
import android.widget.RemoteViews
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Standards-based Android AutofillService. It never reads a vault cache itself: the service
 * always asks Android to launch [AutofillAuthActivity], which must complete a fresh biometric
 * Keystore operation before the shared Rust coordinator can return any credential value.
 */
@androidx.annotation.RequiresApi(Build.VERSION_CODES.O)
class HasilanAutofillService : AutofillService() {
  companion object {
    private val verifier: ExecutorService = Executors.newSingleThreadExecutor { runnable ->
      Thread(runnable, "hasilan-autofill-trust").apply { isDaemon = true }
    }
  }

  override fun onFillRequest(
    request: FillRequest,
    cancellationSignal: CancellationSignal,
    callback: FillCallback,
  ) {
    if (cancellationSignal.isCanceled) return
    val structure = request.fillContexts.lastOrNull()?.structure
    val target = AutofillTarget.from(structure)
    if (target == null) {
      callback.onSuccess(null)
      return
    }
    // AssistStructure values are supplied by the requesting app. Resolve its package/domain
    // relation off the binder thread before exposing even the vault-unlock affordance.
    verifier.execute {
      val trusted = AutofillTrust.resolve(applicationContext, target)
      if (cancellationSignal.isCanceled) return@execute
      if (trusted.isEmpty()) {
        callback.onSuccess(null)
        return@execute
      }
      val authIntent = Intent(this, AutofillAuthActivity::class.java)
      val flags = PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE
      val identity = "${target.packageName}:${target.webOrigin ?: trusted.joinToString(",")}".take(512)
      val pendingIntent = PendingIntent.getActivity(this, identity.hashCode(), authIntent, flags)
      val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
        setTextViewText(android.R.id.text1, getString(R.string.autofill_unlock))
      }
      val response = FillResponse.Builder()
        .setAuthentication(target.ids.toTypedArray(), pendingIntent.intentSender, presentation)
        .apply {
          if (target.saveIds.isNotEmpty()) {
            setSaveInfo(
              SaveInfo.Builder(
                SaveInfo.SAVE_DATA_TYPE_USERNAME or SaveInfo.SAVE_DATA_TYPE_PASSWORD,
                target.saveIds.toTypedArray(),
              ).build(),
            )
          }
        }
        .build()
      callback.onSuccess(response)
    }
  }

  override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
    val structure = request.fillContexts.lastOrNull()?.structure
    val target = AutofillTarget.from(structure)
    val values = AutofillTarget.values(structure)
    val password = values?.second
    if (target == null || password.isNullOrBlank()) {
      callback.onSuccess()
      return
    }
    verifier.execute {
      val origins = AutofillTrust.resolve(applicationContext, target)
      if (origins.isEmpty()) {
        callback.onSuccess()
        return@execute
      }
      val intent = Intent(this, AutofillSaveActivity::class.java).apply {
        putStringArrayListExtra(AutofillSaveActivity.EXTRA_ORIGINS, ArrayList(origins))
        putExtra(AutofillSaveActivity.EXTRA_PACKAGE, target.packageName)
        putExtra(AutofillSaveActivity.EXTRA_USERNAME, values.first)
        putExtra(AutofillSaveActivity.EXTRA_PASSWORD, password)
      }
      val pending = PendingIntent.getActivity(
        this,
        (origins.joinToString(",") + password.length).hashCode(),
        intent,
        PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE,
      )
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        completeSaveWithAuthentication(callback, pending)
      } else {
        // Android 8.0/8.1 cannot return an authenticated save IntentSender. Do not save secrets
        // without the same explicit biometric confirmation used on newer releases.
        callback.onSuccess()
      }
    }
  }

  @androidx.annotation.RequiresApi(Build.VERSION_CODES.P)
  private fun completeSaveWithAuthentication(callback: SaveCallback, pending: PendingIntent) {
    callback.onSuccess(pending.intentSender)
  }
}
