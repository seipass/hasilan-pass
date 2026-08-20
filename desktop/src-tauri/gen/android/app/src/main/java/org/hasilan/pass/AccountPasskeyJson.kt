package org.hasilan.pass

import com.fasterxml.jackson.databind.ObjectMapper

/** Validates and unwraps the browser-shaped WebAuthn option wrapper for Credential Manager. */
internal object AccountPasskeyJson {
  private const val MAX_OPTIONS_BYTES = 262_144
  private val mapper = ObjectMapper()

  fun publicKeyOptions(value: String): String? {
    if (value.isBlank() || value.length > MAX_OPTIONS_BYTES) return null
    return try {
      val publicKey = mapper.readTree(value).path("publicKey")
      if (!publicKey.isObject || publicKey.path("challenge").asText().isBlank()) return null
      mapper.writeValueAsString(publicKey)
    } catch (_: Exception) {
      null
    }
  }
}
