package org.hasilan.pass

import android.app.PendingIntent
import android.content.Intent
import android.os.CancellationSignal
import android.os.Build
import android.os.OutcomeReceiver
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.provider.Action
import androidx.credentials.provider.AuthenticationAction
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.ProviderClearCredentialStateRequest

/** Android 14+ Credential Manager provider for Hasilan Pass passwords and passkeys. */
@androidx.annotation.RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class HasilanCredentialProviderService : CredentialProviderService() {
  override fun onBeginGetCredentialRequest(
    request: BeginGetCredentialRequest,
    cancellationSignal: CancellationSignal,
    callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
  ) {
    if (cancellationSignal.isCanceled) return
    val intent = Intent(this, CredentialProviderAuthActivity::class.java).apply {
      action = CredentialProviderAuthActivity.ACTION_UNLOCK
    }
    val pending = PendingIntent.getActivity(
      this,
      71,
      intent,
      PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )
    if (BiometricVault.hasEnvelope(this) && BiometricVault.isAvailable(this)) {
      callback.onResult(
        BeginGetCredentialResponse(
          authenticationActions = listOf(
            AuthenticationAction(getString(R.string.autofill_unlock), pending),
          ),
        ),
      )
    } else {
      callback.onResult(
        BeginGetCredentialResponse(
          actions = listOf(Action(getString(R.string.open_app_to_unlock), pending)),
        ),
      )
    }
  }

  override fun onBeginCreateCredentialRequest(
    request: BeginCreateCredentialRequest,
    cancellationSignal: CancellationSignal,
    callback: OutcomeReceiver<BeginCreateCredentialResponse, androidx.credentials.exceptions.CreateCredentialException>,
  ) {
    if (cancellationSignal.isCanceled) return
    if (request !is BeginCreatePublicKeyCredentialRequest) {
      callback.onResult(BeginCreateCredentialResponse())
      return
    }
    val intent = Intent(this, CredentialProviderCreateActivity::class.java)
    val pending = PendingIntent.getActivity(
      this,
      73,
      intent,
      PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )
    callback.onResult(
      BeginCreateCredentialResponse(
        listOf(CreateEntry(getString(R.string.vault_account), pending)),
      ),
    )
  }

  override fun onClearCredentialStateRequest(
    request: ProviderClearCredentialStateRequest,
    cancellationSignal: CancellationSignal,
    callback: OutcomeReceiver<Void?, ClearCredentialException>,
  ) {
    // Hasilan Pass does not persist a last-used provider selection.
    callback.onResult(null)
  }
}
