package org.hasilan.pass

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.enableEdgeToEdge

class MainActivity : TauriActivity() {
  /**
   * Route the Android predictive-back gesture through the WebView history. The React shell adds
   * one history entry for an open editor, so Back first dismisses that sensitive modal instead
   * of immediately finishing the activity. With no in-app history, Tauri falls through to the
   * normal Android finish behavior.
   */
  override val handleBackNavigation: Boolean = true

  override fun onCreate(savedInstanceState: Bundle?) {
    window.setFlags(
      WindowManager.LayoutParams.FLAG_SECURE,
      WindowManager.LayoutParams.FLAG_SECURE,
    )
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
  }

  override fun onStop() {
    // Drop Rust-held plaintext as soon as the main vault is no longer visible. Autofill and
    // Credential Manager independently require a fresh BiometricPrompt before they can unlock.
    if (VaultLifecyclePolicy.locksOnStop()) {
      AutofillNative.lockApp()
      AutofillNative.lockNative()
    }
    super.onStop()
  }
}
