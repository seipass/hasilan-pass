package org.hasilan.pass

import android.app.Activity
import android.content.Intent
import android.graphics.ImageFormat
import android.os.Bundle
import android.view.WindowManager
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.google.common.util.concurrent.ListenableFuture
import java.util.concurrent.Executor

/** Local-only camera scanner for `otpauth://totp/...` QR payloads. */
class QrScanActivity : FragmentActivity() {
  companion object {
    const val EXTRA_TOTP = "org.hasilan.pass.qr.TOTP"
  }

  private var completed = false
  private var cameraProvider: ProcessCameraProvider? = null

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
    val previewView = PreviewView(this)
    setContentView(previewView)
    val cameraFuture: ListenableFuture<ProcessCameraProvider> = ProcessCameraProvider.getInstance(this)
    cameraFuture.addListener({
      try {
        cameraProvider = cameraFuture.get()
        bindCamera(previewView)
      } catch (_: Exception) {
        finish()
      }
    }, mainExecutor())
  }

  private fun bindCamera(previewView: PreviewView) {
    val provider = cameraProvider ?: return
    val preview = Preview.Builder().build().also { it.surfaceProvider = previewView.surfaceProvider }
    val analysis = ImageAnalysis.Builder()
      .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
      .build()
    analysis.setAnalyzer(mainExecutor()) { proxy ->
      if (completed) {
        proxy.close()
        return@setAnalyzer
      }
      try {
        val payload = luminanceBytes(proxy)
          ?.let { (bytes, width, height) -> TotpQrDecoder.decode(bytes, width, height) }
        if (payload != null && !completed) complete(payload)
      } finally {
        proxy.close()
      }
    }
    try {
      provider.unbindAll()
      provider.bindToLifecycle(this, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
    } catch (_: Exception) {
      finish()
    }
  }

  /** Copies only the luminance plane; camera color pixels are neither saved nor sent anywhere. */
  private fun luminanceBytes(proxy: ImageProxy): Triple<ByteArray, Int, Int>? {
    if (proxy.format != ImageFormat.YUV_420_888 || proxy.planes.isEmpty()) return null
    val width = proxy.width
    val height = proxy.height
    if (width <= 0 || height <= 0 || width.toLong() * height > 16L * 1024L * 1024L) return null
    val plane = proxy.planes[0]
    val buffer = plane.buffer.duplicate()
    val output = ByteArray(width * height)
    for (row in 0 until height) {
      val rowStart = row * plane.rowStride
      for (column in 0 until width) {
        val position = rowStart + column * plane.pixelStride
        if (position < 0 || position >= buffer.limit()) return null
        output[row * width + column] = buffer.get(position)
      }
    }
    return Triple(output, width, height)
  }

  private fun complete(value: String) {
    completed = true
    cameraProvider?.unbindAll()
    setResult(Activity.RESULT_OK, Intent().putExtra(EXTRA_TOTP, value))
    finish()
  }

  override fun onDestroy() {
    cameraProvider?.unbindAll()
    super.onDestroy()
  }

  private fun mainExecutor(): Executor = ContextCompat.getMainExecutor(this)
}
