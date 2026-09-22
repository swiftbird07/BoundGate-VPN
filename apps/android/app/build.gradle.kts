plugins {
    id("com.android.application")
}

// set by build.sh: the release tag and a code that grows with it
val bgVersion = (findProperty("bgVersion") as String?) ?: "dev"
val bgVersionCode = ((findProperty("bgVersionCode") as String?) ?: "1").toInt()

android {
    namespace = "com.net407.boundgate"
    compileSdk = 36
    buildToolsVersion = "36.1.0"

    defaultConfig {
        applicationId = "com.net407.boundgate"
        // KeyInfo.securityLevel (StrongBox or TEE) needs Android 12
        minSdk = 31
        targetSdk = 36
        versionCode = bgVersionCode
        versionName = bgVersion
    }

    // libboundgate.so per ABI, built from cmd/libboundgate by build.sh
    sourceSets.getByName("main").jniLibs.directories.add(
        (findProperty("bgJniLibs") as String?) ?: "../../../build/android/jniLibs",
    )

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
        }
    }
    packaging {
        // the core is stripped already; keep it as built
        jniLibs.keepDebugSymbols.add("**/libboundgate.so")
    }
}
