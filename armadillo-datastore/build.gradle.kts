plugins {
  id("com.android.library")
  id("kotlin-android")
  id ("org.jetbrains.kotlin.plugin.serialization") version "1.4.10"
}

android {
  val compileSdkVersion: Int by rootProject.extra
  val buildToolsVersion: String by rootProject.extra

  compileSdkVersion(compileSdkVersion)
  buildToolsVersion(buildToolsVersion)

  defaultConfig {
    val minSdkVersion: Int by rootProject.extra
    val targetSdkVersion: Int by rootProject.extra

    minSdkVersion(minSdkVersion)
    targetSdkVersion(targetSdkVersion)
    versionCode = 1
    versionName = "0.1.0"

    testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    consumerProguardFiles("consumer-rules.pro")
  }

  buildTypes {
    getByName("release") {
      isMinifyEnabled = false
      proguardFiles(
          getDefaultProguardFile("proguard-android-optimize.txt"),
          "proguard-rules.pro"
      )
    }
  }

  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
  }

  kotlinOptions {
    jvmTarget = JavaVersion.VERSION_1_8.toString()
  }
}

dependencies {
  implementation(project(":armadillo"))

  implementation("org.jetbrains.kotlin:kotlin-stdlib:1.4.30")

  implementation("androidx.core:core-ktx:1.3.2")
  implementation("androidx.appcompat:appcompat:1.2.0")
  implementation("androidx.datastore:datastore-core:1.0.0-alpha07")

  implementation("org.jetbrains.kotlinx:kotlinx-serialization-protobuf:1.0.0")

  testImplementation("junit:junit:4.13.2")
  androidTestImplementation("androidx.test.ext:junit:1.1.2")
  androidTestImplementation("androidx.test.espresso:espresso-core:3.3.0")
  androidTestImplementation("org.bouncycastle:bcprov-jdk15on:1.67")
  androidTestImplementation("org.mindrot:jbcrypt:0.4")
  androidTestImplementation("androidx.test.ext:junit:1.1.2")
  androidTestImplementation("androidx.test:rules:1.3.0")
}
