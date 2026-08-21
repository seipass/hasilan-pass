package org.hasilan.pass

import android.view.WindowManager
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Device/emulator checks for the concrete Android Keystore, biometric-envelope, and lifecycle paths. */
@RunWith(AndroidJUnit4::class)
class AndroidSecurityInstrumentedTest {
  private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

  @Before
  fun clearBiometricEnvelope() {
    BiometricVault.clear(context)
  }

  @Test
  fun storageKeystoreRoundTripDoesNotPersistPlaintext() {
    val plaintext = "instrumented-keystore-check".toByteArray()
    val encrypted = AndroidKeystore.encryptStorage(plaintext)
    assertFalse(encrypted.contains("instrumented-keystore-check"))
    val decrypted = AndroidKeystore.decryptStorage(encrypted)
    assertArrayEquals(plaintext, decrypted)
    plaintext.fill(0)
    decrypted?.fill(0)
  }

  @Test
  fun biometricEnvelopeStartsAbsentAfterExplicitClear() {
    assertFalse(BiometricVault.hasEnvelope(context))
  }

  @Test
  fun launchAppliesSecureWindowAndLifecyclePolicy() {
    // Do not close the scenario explicitly: Tauri's Android event loop calls
    // process.exit() during Activity destruction, which races the emulator EGL
    // teardown and aborts the instrumentation process. The runner cleans up the
    // target package after the test process exits.
    val scenario = ActivityScenario.launch(MainActivity::class.java)
    scenario.onActivity { activity ->
      assertTrue(
        activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0,
      )
      assertTrue(activity.handleBackNavigation)
    }
    assertTrue(VaultLifecyclePolicy.locksOnStop())
  }
}
