package org.hasilan.pass

import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Bundle
import android.os.Build
import android.view.WindowManager
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.widget.RemoteViews
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.Executors

/** Biometric-only completion activity for a system AutofillService authentication response. */
@androidx.annotation.RequiresApi(Build.VERSION_CODES.O)
class AutofillAuthActivity : FragmentActivity() {
  private val verifier = Executors.newSingleThreadExecutor { runnable ->
    Thread(runnable, "hasilan-autofill-auth-trust").apply { isDaemon = true }
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
    if (!AutofillNative.initialize(applicationInfo.dataDir)) {
      finish()
      return
    }
    val structure = intent.assistStructure()
    val target = AutofillTarget.from(structure)
    if (target == null) {
      finish()
      return
    }
    // Repeat the service-side trust check on the authenticated Activity's fresh AssistStructure.
    // This closes the gap between a FillRequest and a later PendingIntent launch.
    verifier.execute {
      val origins = AutofillTrust.resolve(applicationContext, target)
      runOnUiThread {
        if (isFinishing || origins.isEmpty()) {
          finish()
          return@runOnUiThread
        }
        unlockAndRespond(target, origins)
      }
    }
  }

  override fun onDestroy() {
    verifier.shutdownNow()
    super.onDestroy()
  }

  private fun unlockAndRespond(target: AutofillTarget, origins: List<String>) {
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
      val candidates = origins
        .flatMap { origin -> parseCandidates(AutofillNative.candidates(origin)) }
        .distinctBy { candidate -> candidate.id }
        .take(50)
      val response = response(target, candidates)
      if (response == null) {
        AutofillNative.lockNative()
        finish()
        return@unwrap
      }
      // Datasets hold copies in the system response; no native plaintext needs to remain alive.
      AutofillNative.lockNative()
      setResult(
        RESULT_OK,
        Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response),
      )
      finish()
    }, {
      finish()
    })
  }

  private fun response(target: AutofillTarget, candidates: List<AutofillCandidate>): FillResponse? {
    if (candidates.isEmpty()) return null
    val builder = FillResponse.Builder()
    candidates.forEach { candidate ->
      val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
        setTextViewText(android.R.id.text1, candidate.name)
      }
      var fields = 0
      val dataset = Dataset.Builder(presentation).apply {
        target.usernameId?.let { id ->
          candidate.username?.let { value ->
            setValue(id, AutofillValue.forText(value))
            fields += 1
          }
        }
        target.passwordId?.let { id ->
          candidate.password?.let { value ->
            setValue(id, AutofillValue.forText(value))
            fields += 1
          }
        }
        target.otpId?.let { id ->
          candidate.totp?.let { value ->
            setValue(id, AutofillValue.forText(value))
            fields += 1
          }
        }
      }.build()
      if (fields > 0) builder.addDataset(dataset)
    }
    return if (candidates.any { candidate ->
        (target.usernameId != null && candidate.username != null) ||
          (target.passwordId != null && candidate.password != null) ||
          (target.otpId != null && candidate.totp != null)
      }) builder.build() else null
  }

  @Suppress("DEPRECATION")
  private fun Intent.assistStructure(): AssistStructure? =
    getParcelableExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE) as? AssistStructure
}
