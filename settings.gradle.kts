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


//interfaces for engines and users
include("cryptography-core")

//mapping from sync to async via dispatcher or channel
//include("cryptography-coroutines")

//TODO: how to test that all engines have same output for same input - cross-engine tests
//include("cryptography-tests")

//high-level API for users
//we need to have separate modules/packages/annotations for algorithms:
// - legacy - for old algorithms, which are not secure anymore, but still used in some cases (e.g. MD5, compatibility, etc)
// - modern - for modern algorithms, which are secure and recommended to use (like in CryptoKit and WebCrypto)
// - other - implemented in different engines, but not in all of them (e.g. ChaCha20, Poly1305, etc)
include("cryptography-algorithms")

//first engines:
include("cryptography-engines:cryptography-engine-jdk") //jvm only
include("cryptography-engines:cryptography-engine-corecrypto") //darwin only
include("cryptography-engines:cryptography-engine-webcrypto") //js(nodejs/browser) only
//include("cryptography-engines:cryptography-engine-nodejs") //nodejs only
//include("cryptography-engines:cryptography-engine-openssl3") //all platforms, starting from linux/macos/windows
//include("cryptography-engines:cryptography-engine-cng") //windows only

//future engines:
//include("cryptography-engines:cryptography-engine-aws") //remote AWS KMS provider
//include("cryptography-engines:cryptography-engine-gcp") //remote GCP KMS provider
//include("cryptography-engines:cryptography-engine-boringssl") //same as openssl
//include("cryptography-engines:cryptography-engine-wolfcrypto") //same as openssl
//include("cryptography-engines:cryptography-engine-tink") //is it needed?

//future features:
// - JWK/JWT support (JOSE)
// - ASN.1/X.509/DER/PEM support (via kx.serialization)

//need:
// - BigInt
// - some new IO
// - auto provider API - not really needed for now
// - C API wrapper
