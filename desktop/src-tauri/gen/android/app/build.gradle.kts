import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("rust")
}

val tauriProperties = Properties().apply {
    val propFile = file("tauri.properties")
    if (propFile.exists()) {
        propFile.inputStream().use { load(it) }
    }
}

val androidReleaseStore = System.getenv("HP_ANDROID_KEYSTORE")
val androidReleaseStorePassword = System.getenv("HP_ANDROID_KEYSTORE_PASSWORD")
val androidReleaseKeyAlias = System.getenv("HP_ANDROID_KEY_ALIAS")
val androidReleaseKeyPassword = System.getenv("HP_ANDROID_KEY_PASSWORD")
val androidReleaseSigningValues = listOf(
    androidReleaseStore,
    androidReleaseStorePassword,
    androidReleaseKeyAlias,
    androidReleaseKeyPassword,
)
val hasAndroidReleaseSigning = androidReleaseSigningValues.all { !it.isNullOrBlank() }
val androidAppLinkHost = System.getenv("HP_ANDROID_APP_LINK_HOST")
  ?.trim()
  ?.lowercase()
  ?.takeIf { it.matches(Regex("[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")) }
  ?: "invalid.hasilan-pass.local"

if (androidReleaseSigningValues.any { !it.isNullOrBlank() } && !hasAndroidReleaseSigning) {
    error("Set all HP_ANDROID_KEYSTORE, HP_ANDROID_KEYSTORE_PASSWORD, HP_ANDROID_KEY_ALIAS, and HP_ANDROID_KEY_PASSWORD values together")
}

android {
    compileSdk = 36
    namespace = "org.hasilan.pass"
    defaultConfig {
        manifestPlaceholders["usesCleartextTraffic"] = "false"
        // A self-hosted deployment can set HP_ANDROID_APP_LINK_HOST and publish its matching
        // Digital Asset Links statement. The safe default claims no public HTTPS host.
        manifestPlaceholders["appLinkHost"] = androidAppLinkHost
        applicationId = "org.hasilan.pass"
        minSdk = 24
        targetSdk = 36
        // Use the AndroidX runner explicitly so connected instrumentation tests do not
        // fall back to the legacy platform runner (which reports a crashed 0-test run).
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        versionCode = tauriProperties.getProperty("tauri.android.versionCode", "1").toInt()
        versionName = tauriProperties.getProperty("tauri.android.versionName", "1.0")
    }
    signingConfigs {
        if (hasAndroidReleaseSigning) {
            create("release") {
                storeFile = file(androidReleaseStore!!)
                storePassword = androidReleaseStorePassword
                keyAlias = androidReleaseKeyAlias
                keyPassword = androidReleaseKeyPassword
            }
        }
    }
    buildTypes {
        getByName("debug") {
            manifestPlaceholders["usesCleartextTraffic"] = "true"
            isDebuggable = true
            isJniDebuggable = true
            isMinifyEnabled = false
            packaging {
                jniLibs.keepDebugSymbols.add("*/arm64-v8a/*.so")
                jniLibs.keepDebugSymbols.add("*/armeabi-v7a/*.so")
                jniLibs.keepDebugSymbols.add("*/x86/*.so")
                jniLibs.keepDebugSymbols.add("*/x86_64/*.so")
            }
        }
        getByName("release") {
            if (hasAndroidReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            }
            isMinifyEnabled = true
            proguardFiles(
                *fileTree(".") { include("**/*.pro") }
                    .plus(getDefaultProguardFile("proguard-android-optimize.txt"))
                    .toList().toTypedArray()
            )
        }
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
    buildFeatures {
        buildConfig = true
    }
}

rust {
    rootDirRel = "../../../"
}

dependencies {
    implementation("androidx.webkit:webkit:1.14.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.credentials:credentials:1.5.0")
    // Tauri's Android runtime uses this version internally. Declaring it here keeps the
    // credential selector parser available to this module and avoids an Android-only parser.
    implementation("com.fasterxml.jackson.core:jackson-databind:2.15.3")
    implementation("androidx.camera:camera-camera2:1.4.2")
    implementation("androidx.camera:camera-core:1.4.2")
    implementation("androidx.camera:camera-lifecycle:1.4.2")
    implementation("androidx.camera:camera-view:1.4.2")
    // Apache-2.0 local QR decoding. Unlike ML Kit this does not pull Google Play Services or
    // Firebase transitively, so a self-hosted vault remains usable on de-Googled Android.
    implementation("com.google.zxing:core:3.5.4")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.lifecycle:lifecycle-process:2.10.0")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test:core-ktx:1.5.0")
    androidTestImplementation("androidx.test.ext:junit:1.1.4")
    androidTestImplementation("androidx.test:runner:1.5.2")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.0")
}

apply(from = "tauri.build.gradle.kts")
