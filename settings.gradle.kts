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

//test tool
listOf("client", "server").forEach { name ->
    include("cryptography-tester-$name")
    project(":cryptography-tester-$name").projectDir = file("cryptography-tester/$name")
}
