plugins { id("com.android.application") }
android {
    namespace = "org.certconcord.holder"
    compileSdk = 35
    defaultConfig { applicationId = "org.certconcord.holder.keyadapter"; minSdk = 30; targetSdk = 35; versionCode = 1; versionName = "1.0.0" }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
}
