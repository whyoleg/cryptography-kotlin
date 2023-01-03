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

//TODO: how to test that all engines have same output for same input - cross-engine tests
// 1. generate random input (per engine) (different data sizes / key sizes)
// 2. run all engines on it's own plaintext/data
// 3. save plaintext + ciphertext (for ciphers) and data + hash (for hashes)
// 4. run all engines on other engines plaintext/data

//models to register engines, serialize, etc
include("cryptography-tests:cryptography-testcase-api")
//read/store results with local file system (f.e. desktop native targets, jvm, nodejs)
include("cryptography-tests:cryptography-testcase-files")
//read/store results with remote (f.e. browser, android, etc)
include("cryptography-tests:cryptography-testcase-client")
include("cryptography-tests:cryptography-testcase-server")

include("cryptography-tests:cryptography-testsuite-api")
//first part, test implementations in place
include("cryptography-tests:cryptography-testsuite-main")
//secnod part, test implementations from other engines
include("cryptography-tests:cryptography-testsuite-cross")

//providers

include("cryptography-providers:cryptography-jdk") //jvm only
include("cryptography-providers:cryptography-apple") //darwin only
include("cryptography-providers:cryptography-webcrypto") //js(nodejs/browser) only
//include("cryptography-openssl") //all platforms, starting from linux/macos/windows
//include("cryptography-openssl3") //all platforms, starting from linux/macos/windows
