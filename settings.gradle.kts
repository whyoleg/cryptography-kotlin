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

//Buffer + Closeable - this module should be removed later
include("cryptography-io")

//core interfaces
// divided in packages per kind of operation (hash, signature, encryption, random, etc)
include("cryptography-core")

include("cryptography-operations")

//default algorithms APIs
// divided in packages per algorithms kind (digest, asymmetric, symmetric, etc)
include("cryptography-algorithms")

//mapping from sync to async via dispatcher or channel
//include("cryptography-coroutines")

//TODO: how to test that all engines have same output for same input - cross-engine tests
// 1. generate random input (per engine) (different data sizes / key sizes)
// 2. run all engines on it's own plaintext/data
// 3. save plaintext + ciphertext (for ciphers) and data + hash (for hashes)
// 4. run all engines on other engines plaintext/data
include("cryptography-tests")

//include("cryptography-engines:cryptography-engine-default") //all platforms - use best fit for every platform
include("cryptography-engines:cryptography-engine-jdk") //jvm only
include("cryptography-engines:cryptography-engine-corecrypto") //darwin only
include("cryptography-engines:cryptography-engine-webcrypto") //js(nodejs/browser) only
//include("cryptography-engines:cryptography-engine-openssl") //all platforms, starting from linux/macos/windows
//include("cryptography-engines:cryptography-engine-openssl3") //all platforms, starting from linux/macos/windows
