enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
    includeBuild("gradle/plugins")
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

rootProject.name = "cryptography-kotlin"

include("cryptography-io")
include("cryptography-random")
include("cryptography-core")

//mapping from sync to async via dispatcher or channel
//include("cryptography-coroutines")

//providers
listOf(
    "jdk", //jvm only
    "apple", //darwin only
    "webcrypto", //js(nodejs/browser) only
    //"openssl", //all platforms, starting from linux/macos/windows
    //"openssl3", //all platforms, starting from linux/macos/windows
).forEach { name ->
    include("cryptography-$name")
    project(":cryptography-$name").projectDir = file("cryptography-providers/cryptography-$name")
}

//test API
listOf("api", "client", "server", "suite").forEach { name ->
    include("cryptography-test-$name")
    project(":cryptography-test-$name").projectDir = file("cryptography-tests/cryptography-test-$name")
}
