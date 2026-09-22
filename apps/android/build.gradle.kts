// AGP 9 compiles Kotlin itself (built-in Kotlin); the classpath entry picks
// the Kotlin compiler it uses.
buildscript {
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath("com.android.tools.build:gradle:9.4.0")
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.4.20")
    }
}
