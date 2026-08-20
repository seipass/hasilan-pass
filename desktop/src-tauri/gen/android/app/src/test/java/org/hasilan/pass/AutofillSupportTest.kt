package org.hasilan.pass

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter

class AutofillSupportTest {
  @Test
  fun passwordCandidatesRejectMalformedOrIncompletePayloads() {
    assertTrue(parseCandidates(null).isEmpty())
    assertTrue(parseCandidates("not json").isEmpty())
    assertTrue(parseCandidates("[{\"id\":\"\",\"name\":\"missing\"}]").isEmpty())
    val candidates = parseCandidates(
      "[{\"id\":\"item-1\",\"name\":\"Example\",\"username\":\"alice\",\"password\":\"secret\"}]",
    )
    assertEquals(1, candidates.size)
    assertEquals("item-1", candidates.single().id)
    assertEquals("alice", candidates.single().username)
    assertEquals("secret", candidates.single().password)
    assertNull(candidates.single().totp)
  }

  @Test
  fun passwordCandidatesKeepTotpOnlyWhenTheSharedCoreReturnedOne() {
    val candidates = parseCandidates(
      "[{\"id\":\"item-1\",\"name\":\"Example\",\"totp\":\"123456\"}]",
    )
    assertEquals("123456", candidates.single().totp)
  }

  @Test
  fun passkeyCandidatesOnlyExposeCompleteNonSecretSelectorData() {
    val candidates = parsePasskeyCandidates(
      "[{\"itemId\":\"item-1\",\"credentialId\":\"credential-1\",\"rpId\":\"example.test\",\"displayName\":\"Alice\",\"userName\":\"alice\"}, {\"itemId\":\"bad\"}]",
    )
    assertEquals(1, candidates.size)
    assertEquals("credential-1", candidates.single().credentialId)
    assertEquals("Alice", candidates.single().displayName)
  }

  @Test
  fun delegatedCredentialOriginMustBeAnHttpsOriginWithoutPathOrCredentials() {
    assertEquals(
      "https://login.example.test",
      CredentialOrigin.canonicalHttpsOrigin("https://LOGIN.example.test:443/"),
    )
    assertEquals(
      "https://login.example.test:8443",
      CredentialOrigin.canonicalHttpsOrigin("https://login.example.test:8443"),
    )
    assertNull(CredentialOrigin.canonicalHttpsOrigin("http://login.example.test"))
    assertNull(CredentialOrigin.canonicalHttpsOrigin("https://user@login.example.test"))
    assertNull(CredentialOrigin.canonicalHttpsOrigin("https://login.example.test/path"))
  }

  @Test
  fun digitalAssetLinksNeedLoginCredentialRelationPackageAndInstalledCertificate() {
    val statement = """
      [{
        "relation": ["delegate_permission/common.get_login_creds"],
        "target": {
          "namespace": "android_app",
          "package_name": "com.example.app",
          "sha256_cert_fingerprints": ["AA:BB:CC"]
        }
      }]
    """.trimIndent()
    assertTrue(AutofillTrust.parsesDigitalAssetLink(statement, "com.example.app", setOf("AA:BB:CC")))
    assertTrue(!AutofillTrust.parsesDigitalAssetLink(statement, "com.example.other", setOf("AA:BB:CC")))
    assertTrue(!AutofillTrust.parsesDigitalAssetLink(statement, "com.example.app", setOf("DD:EE:FF")))
    assertTrue(!AutofillTrust.parsesDigitalAssetLink(
      statement.replace("get_login_creds", "handle_all_urls"),
      "com.example.app",
      setOf("AA:BB:CC"),
    ))
  }

  @Test
  fun accountPasskeyOptionsMapOnlyThePublicKeyMember() {
    val options = AccountPasskeyJson.publicKeyOptions(
      """{"publicKey":{"challenge":"challenge","rp":{"id":"example.test"}}}""",
    )
    assertTrue(options?.contains("challenge") == true)
    assertTrue(options?.contains("publicKey") == false)
    assertNull(AccountPasskeyJson.publicKeyOptions("{\"publicKey\":{}}"))
    assertNull(AccountPasskeyJson.publicKeyOptions("{\"challenge\":\"missing wrapper\"}"))
  }

  @Test
  fun lifecyclePolicyAlwaysLocksOnStop() {
    assertTrue(VaultLifecyclePolicy.locksOnStop())
  }

  @Test
  fun attachmentFileNamesCannotEscapePrivateStaging() {
    assertEquals("invoice.pdf", safeAttachmentFileName("invoice.pdf"))
    assertEquals(".._private.txt", safeAttachmentFileName("../private.txt"))
    assertEquals("report_final.csv", safeAttachmentFileName("report\\final.csv"))
    assertNull(safeAttachmentFileName("   "))
    assertNull(safeAttachmentFileName("."))
    assertNull(safeAttachmentFileName(".."))
  }

  @Test
  fun localQrDecoderReturnsOnlyBoundedTotpPayloads() {
    val totp = "otpauth://totp/Hasilan:alice?secret=JBSWY3DPEHPK3PXP&issuer=Hasilan"
    assertEquals(totp, TotpQrDecoder.decode(qrLuminance(totp), 160, 160))
    assertNull(TotpQrDecoder.decode(qrLuminance("https://example.test/not-a-totp"), 160, 160))
  }

  private fun qrLuminance(value: String): ByteArray {
    val matrix = QRCodeWriter().encode(value, BarcodeFormat.QR_CODE, 160, 160)
    return ByteArray(160 * 160) { index ->
      val x = index % 160
      val y = index / 160
      if (matrix[x, y]) 0 else 0xff.toByte()
    }
  }
}
