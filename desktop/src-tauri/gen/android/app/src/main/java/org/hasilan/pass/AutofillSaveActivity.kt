package org.hasilan.pass

import android.app.AlertDialog
import android.os.Bundle
import android.view.WindowManager
import android.webkit.URLUtil
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.Executors

/** Explicit, user-confirmed save flow returned from [HasilanAutofillService.onSaveRequest]. */
@androidx.annotation.RequiresApi(android.os.Build.VERSION_CODES.O)
class AutofillSaveActivity : FragmentActivity() {
  private val verifier = Executors.newSingleThreadExecutor { runnable ->
    Thread(runnable, "hasilan-autofill-save-trust").apply { isDaemon = true }
  }

  companion object {
    const val EXTRA_ORIGINS = "org.hasilan.pass.autofill.ORIGINS"
    const val EXTRA_PACKAGE = "org.hasilan.pass.autofill.PACKAGE"
    const val EXTRA_USERNAME = "org.hasilan.pass.autofill.USERNAME"
    const val EXTRA_PASSWORD = "org.hasilan.pass.autofill.PASSWORD"
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
    if (!AutofillNative.initialize(applicationInfo.dataDir)) {
      finish()
      return
    }
    val origins = intent.getStringArrayListExtra(EXTRA_ORIGINS).orEmpty()
    val callingPackage = intent.getStringExtra(EXTRA_PACKAGE)
    val password = intent.getStringExtra(EXTRA_PASSWORD)
    val username = intent.getStringExtra(EXTRA_USERNAME)
    if (
      origins.isEmpty() || callingPackage.isNullOrBlank() || password.isNullOrBlank() ||
        origins.any { !URLUtil.isHttpsUrl(it) }
    ) {
      finish()
      return
    }
    val dialog = AlertDialog.Builder(this)
      .setTitle(R.string.save_login_title)
      .setMessage(R.string.save_login_message)
      .setNegativeButton(R.string.cancel) { _, _ -> finish() }
      .setOnCancelListener { finish() }
    if (origins.size == 1) {
      dialog.setPositiveButton(R.string.save) { _, _ ->
        verifyAndSave(origins.single(), callingPackage, username, password)
      }
    } else {
      dialog.setItems(origins.map { android.net.Uri.parse(it).host ?: it }.toTypedArray()) { _, index ->
        verifyAndSave(origins[index], callingPackage, username, password)
      }
    }
    dialog.show()
  }

  override fun onDestroy() {
    verifier.shutdownNow()
    super.onDestroy()
  }

  private fun verifyAndSave(origin: String, callingPackage: String, username: String?, password: String) {
    verifier.execute {
      val target = AutofillTarget(origin, callingPackage, null, null, null)
      val stillTrusted = AutofillTrust.resolve(applicationContext, target).contains(origin)
      runOnUiThread {
        if (stillTrusted && !isFinishing) save(origin, username, password) else finish()
      }
    }
  }

  private fun save(origin: String, username: String?, password: String) {
    val host = android.net.Uri.parse(origin).host ?: "Login"
    val context = AutofillNative.unlockContext() ?: run {
      finish()
      return
    }
    BiometricVault.unwrap(this, context, { key ->
      val unlocked = AutofillNative.unlock(key)
      key.fill(0)
      if (unlocked) AutofillNative.saveLogin(origin, username, password, host)
      AutofillNative.lockNative()
      finish()
    }, { finish() })
  }
}
