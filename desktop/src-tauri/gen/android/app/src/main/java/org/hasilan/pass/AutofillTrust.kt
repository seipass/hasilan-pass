package org.hasilan.pass

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import androidx.annotation.RequiresApi
import com.fasterxml.jackson.databind.ObjectMapper
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.util.Locale

/**
 * Verifies an Autofill request before any vault metadata or secret is exposed.
 *
 * A browser request is accepted only if its installed signing certificate appears in the public
 * privileged-browser list used by Android Credential Manager. A native app request is accepted
 * only after Android has verified an App Link and this provider finds an additional
 * `delegate_permission/common.get_login_creds` Digital Asset Links relation for that exact
 * package and signing certificate. Android 8--11 native-app requests intentionally fail closed:
 * those releases cannot provide the verified-domain signal used here.
 */
internal object AutofillTrust {
  private const val MAX_JSON_BYTES = 128 * 1024
  private const val DAL_RELATION = "delegate_permission/common.get_login_creds"
  private val json = ObjectMapper()

  /** Returns only origins whose relationship to the requesting signed package is verified. */
  fun resolve(context: Context, target: AutofillTarget): List<String> {
    val packageName = target.packageName ?: return emptyList()
    val directOrigin = target.webOrigin
    if (directOrigin != null) {
      if (CredentialOrigin.isTrustedBrowser(context, packageName)) return listOf(directOrigin)
      return if (hasDigitalAssetLink(context, directOrigin, packageName)) listOf(directOrigin) else emptyList()
    }
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return emptyList()
    return verifiedAppLinkOrigins(context, packageName)
      .filter { origin -> hasDigitalAssetLink(context, origin, packageName) }
      .distinct()
      .take(8)
  }

  internal fun hasDigitalAssetLink(context: Context, origin: String, packageName: String): Boolean {
    val canonicalOrigin = CredentialOrigin.canonicalHttpsOrigin(origin) ?: return false
    val fingerprints = signingFingerprints(context, packageName)
    if (fingerprints.isEmpty()) return false
    val assetLinks = downloadJson("$canonicalOrigin/.well-known/assetlinks.json") ?: return false
    return parsesDigitalAssetLink(assetLinks, packageName, fingerprints)
  }

  /** Pure parser used by unit tests; certificates are compared only after normalization. */
  internal fun parsesDigitalAssetLink(
    assetLinks: String,
    packageName: String,
    fingerprints: Set<String>,
  ): Boolean {
    return try {
      val statements = json.readTree(assetLinks)
      if (!statements.isArray) return false
      statements.any { statement ->
        statement.isObject &&
          statement.path("relation").isArray &&
          statement.path("relation").any { it.asText() == DAL_RELATION } &&
          statement.path("target").path("namespace").asText() == "android_app" &&
          statement.path("target").path("package_name").asText() == packageName &&
          statement.path("target").path("sha256_cert_fingerprints").isArray &&
          statement.path("target").path("sha256_cert_fingerprints").any {
            normalizeFingerprint(it.asText()) in fingerprints.map(::normalizeFingerprint).toSet()
          }
      }
    } catch (_: Exception) {
      false
    }
  }

  @RequiresApi(Build.VERSION_CODES.S)
  private fun verifiedAppLinkOrigins(context: Context, packageName: String): List<String> {
    val manager = context.getSystemService(android.content.pm.verify.domain.DomainVerificationManager::class.java)
      ?: return emptyList()
    val state = try {
      manager.getDomainVerificationUserState(packageName)
    } catch (_: PackageManager.NameNotFoundException) {
      return emptyList()
    } catch (_: SecurityException) {
      return emptyList()
    }
    return state?.hostToStateMap
      ?.asSequence()
      ?.filter { (_, domainState) ->
        domainState == android.content.pm.verify.domain.DomainVerificationUserState.DOMAIN_STATE_VERIFIED
      }
      ?.mapNotNull { (host, _) -> CredentialOrigin.canonicalHttpsOrigin("https://$host") }
      ?.take(8)
      ?.toList()
      ?: emptyList()
  }

  internal fun signingFingerprints(context: Context, packageName: String): Set<String> {
    val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      PackageManager.GET_SIGNING_CERTIFICATES
    } else {
      @Suppress("DEPRECATION") PackageManager.GET_SIGNATURES
    }
    val info = try {
      context.packageManager.getPackageInfo(packageName, flags)
    } catch (_: PackageManager.NameNotFoundException) {
      return emptySet()
    } catch (_: SecurityException) {
      return emptySet()
    }
    val signatures = signatures(info)
    return signatures.mapNotNull { signature ->
      try {
        val certificate = CertificateFactory.getInstance("X.509").generateCertificate(signature.toByteArray().inputStream())
        val digest = MessageDigest.getInstance("SHA-256").digest(certificate.encoded)
        digest.joinToString(":") { byte -> "%02X".format(Locale.ROOT, byte) }
      } catch (_: Exception) {
        null
      }
    }.toSet()
  }

  @Suppress("DEPRECATION")
  private fun signatures(info: PackageInfo): Array<android.content.pm.Signature> =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      info.signingInfo?.let { signing ->
        if (signing.hasMultipleSigners()) signing.apkContentsSigners else signing.signingCertificateHistory
      } ?: emptyArray()
    } else {
      info.signatures ?: emptyArray()
    }

  private fun downloadJson(address: String): String? {
    val parsed = try {
      URI(address)
    } catch (_: Exception) {
      return null
    }
    if (parsed.scheme != "https" || parsed.host.isNullOrBlank()) return null
    val connection = try {
      URL(address).openConnection() as HttpURLConnection
    } catch (_: Exception) {
      return null
    }
    connection.apply {
      connectTimeout = 3_000
      readTimeout = 3_000
      useCaches = false
      instanceFollowRedirects = false
      requestMethod = "GET"
      setRequestProperty("Accept", "application/json")
    }
    return try {
      if (connection.responseCode != HttpURLConnection.HTTP_OK) return null
      if (connection.contentLengthLong > MAX_JSON_BYTES) return null
      val output = ByteArrayOutputStream()
      connection.inputStream.use { input ->
        val buffer = ByteArray(8_192)
        while (true) {
          val read = input.read(buffer)
          if (read < 0) break
          if (output.size() + read > MAX_JSON_BYTES) return null
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

  private fun normalizeFingerprint(value: String): String =
    value.filter { it.isLetterOrDigit() }.uppercase(Locale.ROOT).chunked(2).joinToString(":")
}
