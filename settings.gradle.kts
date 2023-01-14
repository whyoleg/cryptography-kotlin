enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
    includeBuild("gradle/buildx") {
        name = "cryptography-buildx"
    }
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
listOf("api", "client", "server").forEach { name ->
    include("cryptography-test-$name")
    project(":cryptography-test-$name").projectDir = file("cryptography-tests/cryptography-test-$name")
}

listOf(
    "api",
    "0-generate",
    "1-compute",
    "2-validate",
).forEach { name ->
    include("cryptography-test-step-$name")
    project(":cryptography-test-step-$name").projectDir = file("cryptography-tests/cryptography-test-suite/step-$name")
}
