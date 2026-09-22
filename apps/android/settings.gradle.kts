// The Android app (docs/ANDROID.md). Built in the image of ./Dockerfile by
// ./build.sh; every dependency is pinned and checked against
// gradle/verification-metadata.xml.
pluginManagement {
    repositories {
        google()
        mavenCentral()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "BoundGate"
include(":app")
