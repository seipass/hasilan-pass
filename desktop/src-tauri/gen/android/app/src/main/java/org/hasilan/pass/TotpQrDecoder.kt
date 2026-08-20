package org.hasilan.pass

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer

/**
 * Small, offline QR decoder for TOTP enrollment.
 *
 * It accepts camera luminance pixels only, returns a bounded `otpauth://totp/` value only, and
 * has no network, Play Services, or vault dependency. Rust remains the authoritative parser when
 * the value is saved; this class deliberately does not interpret the URI's secret or parameters.
 */
internal object TotpQrDecoder {
  private const val MAX_QR_CHARS = 4_096

  fun decode(luminance: ByteArray, width: Int, height: Int): String? {
    val pixelCount = width.toLong() * height.toLong()
    if (width <= 0 || height <= 0 || pixelCount != luminance.size.toLong()) return null
    var source = PlanarYUVLuminanceSource(luminance, width, height, 0, 0, width, height, false)
    repeat(4) {
      val result = try {
        MultiFormatReader().apply {
          setHints(
            mapOf(
              DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
              DecodeHintType.TRY_HARDER to true,
            ),
          )
        }.decodeWithState(BinaryBitmap(HybridBinarizer(source))).text
      } catch (_: Exception) {
        null
      }
      if (result != null) {
        return result.takeIf(::isBoundedTotpUri)
      }
      if (!source.isRotateSupported) return null
      source = source.rotateCounterClockwise() as PlanarYUVLuminanceSource
    }
    return null
  }

  fun isBoundedTotpUri(value: String): Boolean =
    value.length <= MAX_QR_CHARS && value.startsWith("otpauth://totp/", ignoreCase = true)
}
