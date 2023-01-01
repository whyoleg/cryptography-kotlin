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
include("cryptography-core")

//mapping from sync to async via dispatcher or channel
//include("cryptography-coroutines")

//TODO: how to test that all engines have same output for same input - cross-engine tests
// 1. generate random input (per engine) (different data sizes / key sizes)
// 2. run all engines on it's own plaintext/data
// 3. save plaintext + ciphertext (for ciphers) and data + hash (for hashes)
// 4. run all engines on other engines plaintext/data
include("cryptography-tests")

//providers

include("cryptography-jdk") //jvm only
include("cryptography-apple") //darwin only
include("cryptography-webcrypto") //js(nodejs/browser) only
//include("cryptography-openssl") //all platforms, starting from linux/macos/windows
//include("cryptography-openssl3") //all platforms, starting from linux/macos/windows
