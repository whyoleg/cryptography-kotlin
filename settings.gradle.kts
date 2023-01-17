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
    project(":cryptography-$name").projectDir = file("cryptography-providers/$name")
}

//test modules
include("cryptography-test-support")
include("cryptography-tests") //TODO: move to providers folder
listOf("client", "server", "suite").forEach { name ->
    val fullName = "cryptography-test-vectors-$name"
    include(fullName)
    project(":$fullName").projectDir = file("cryptography-test-vectors/$name")
}
