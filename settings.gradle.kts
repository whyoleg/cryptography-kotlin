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

include("cryptography-providers:cryptography-jdk") //jvm only
include("cryptography-providers:cryptography-apple") //darwin only
include("cryptography-providers:cryptography-webcrypto") //js(nodejs/browser) only
//include("cryptography-openssl") //all platforms, starting from linux/macos/windows
//include("cryptography-openssl3") //all platforms, starting from linux/macos/windows

//tests
include("cryptography-tests:cryptography-test-api")
include("cryptography-tests:cryptography-test-client")
include("cryptography-tests:cryptography-test-server")

include("cryptography-tests:cryptography-testsuite-main")
