package org.hasilan.pass

import androidx.credentials.provider.CallingAppInfo
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.util.Locale

/**
 * Resolves an origin asserted by a browser on behalf of a relying party.
 *
 * The Android framework exposes a delegated origin only after the provider supplies a
 * certificate-pinned caller allowlist. Google publishes the list used by Google Password
 * Manager; `CallingAppInfo` performs the package and signing-certificate verification locally.
 * A direct Android app has no browser-delegated origin. In that case [trustedPasskeyOrigin]
 * derives an HTTPS RP origin only after the RP's Digital Asset Links statement delegates login
 * credentials to the installed calling package and signing certificate.
 */
internal object CredentialOrigin {
  private const val PRIVILEGED_APPS_URL =
    "https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json"
  private const val MAX_ALLOWLIST_BYTES = 128 * 1024

  fun trustedBrowserOrigin(callingAppInfo: CallingAppInfo?): String? {
    val calling = callingAppInfo ?: return null
    if (!calling.isOriginPopulated()) return null
    val allowlist = downloadPrivilegedAppsAllowlist() ?: return null
    val origin = try {
      calling.getOrigin(allowlist)
    } catch (_: IllegalArgumentException) {
      null
    } catch (_: IllegalStateException) {
      null
    } ?: return null
    return canonicalHttpsOrigin(origin)
  }

  /**
   * Resolves the only origin that may be placed in a WebAuthn client-data response.
   *
   * The browser route preserves the origin Android verified. For a native caller, the requested
   * RP ID is not trusted on its own: the RP host must publish a bounded HTTPS Asset Links document
   * with `delegate_permission/common.get_login_creds` for the caller's installed certificate.
   */
  fun trustedPasskeyOrigin(
    context: android.content.Context,
    callingAppInfo: CallingAppInfo?,
    rpId: String,
  ): String? {
    if (rpId.isBlank() || rpId.length > 253) return null
    val browserOrigin = trustedBrowserOrigin(callingAppInfo)
    if (browserOrigin != null) return browserOrigin.takeIf { originMatchesRpId(it, rpId) }
    val packageName = callingAppInfo?.packageName ?: return null
    val nativeOrigin = canonicalHttpsOrigin("https://$rpId") ?: return null
    return nativeOrigin.takeIf {
      AutofillTrust.hasDigitalAssetLink(context, nativeOrigin, packageName)
    }
  }

  /** Checks a browser package against the same public signed-browser allowlist. */
  fun isTrustedBrowser(context: android.content.Context, packageName: String): Boolean {
    val allowlist = downloadPrivilegedAppsAllowlist() ?: return false
    val expected = try {
      val apps = com.fasterxml.jackson.databind.ObjectMapper().readTree(allowlist).path("apps")
      if (!apps.isArray) return false
      apps.asSequence()
        .filter { app -> app.path("type").asText() == "android" }
        .filter { app -> app.path("info").path("package_name").asText() == packageName }
        .flatMap { app -> app.path("info").path("signatures").asSequence() }
        .map { signature -> signature.path("cert_fingerprint_sha256").asText() }
        .map { fingerprint -> normalizeFingerprint(fingerprint) }
        .filter { it.isNotBlank() }
        .toSet()
    } catch (_: Exception) {
      return false
    }
    return expected.isNotEmpty() && AutofillTrust.signingFingerprints(context, packageName).any { it in expected }
  }

  private fun downloadPrivilegedAppsAllowlist(): String? {
    val connection = (URL(PRIVILEGED_APPS_URL).openConnection() as HttpURLConnection).apply {
      connectTimeout = 3_000
      readTimeout = 3_000
      useCaches = false
      instanceFollowRedirects = false
      requestMethod = "GET"
    }
    return try {
      if (connection.responseCode != HttpURLConnection.HTTP_OK) return null
      if (connection.contentLengthLong > MAX_ALLOWLIST_BYTES) return null
      val output = ByteArrayOutputStream()
      connection.inputStream.use { input ->
        val buffer = ByteArray(8_192)
        while (true) {
          val read = input.read(buffer)
          if (read < 0) break
          if (output.size() + read > MAX_ALLOWLIST_BYTES) return null
          output.write(buffer, 0, read)
        }
      }
      output.toString(Charsets.UTF_8.name())
    } catch (_: Exception) {
      null
    } finally {
      connection.disconnect()
    }
  }

  internal fun canonicalHttpsOrigin(value: String): String? {
    return try {
      val uri = URI(value)
      val host = uri.host?.lowercase(Locale.ROOT) ?: return null
      if (
        uri.scheme?.lowercase(Locale.ROOT) != "https" ||
        uri.rawUserInfo != null ||
        uri.rawPath !in listOf(null, "", "/") ||
        uri.rawQuery != null ||
        uri.rawFragment != null
      ) {
        return null
      }
      val port = uri.port.takeUnless { it == 443 }
      URI("https", null, host, port ?: -1, null, null, null).toASCIIString()
    } catch (_: Exception) {
      null
    }
  }

  private fun originMatchesRpId(origin: String, rpId: String): Boolean {
    val host = try {
      URI(origin).host?.lowercase(Locale.ROOT)
    } catch (_: Exception) {
      null
    } ?: return false
    val canonicalRpId = rpId.trim().trimEnd('.').lowercase(Locale.ROOT)
    return host == canonicalRpId || host.endsWith(".$canonicalRpId")
  }

  private fun normalizeFingerprint(value: String): String =
    value.filter { it.isLetterOrDigit() }.uppercase(Locale.ROOT).chunked(2).joinToString(":")
}
