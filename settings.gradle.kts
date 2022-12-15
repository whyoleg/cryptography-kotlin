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

include("cryptography-api")

//contains common properties/builders
//include("cryptography-algorithms")
//TODO: is it needed?
//include("cryptography-tests")
//mapping from sync to async via dispatcher or channel
//include("cryptography-coroutines")

//first engines:
//include("cryptography-engines:cryptography-engine-jdk") //jvm only
//include("cryptography-engines:cryptography-engine-corecrypto") //darwin only
//include("cryptography-engines:cryptography-engine-webcrypto") //js(nodejs/browser) only
//include("cryptography-engines:cryptography-engine-nodejs") //nodejs only
//include("cryptography-engines:cryptography-engine-openssl3") //all platforms, starting from linux/macos/windows
//include("cryptography-engines:cryptography-engine-cng") //windows only

//future engines:
//include("cryptography-provider-aws") //remote AWS KMS provider
//include("cryptography-provider-gcp") //remote GCP KMS provider
//include("cryptography-provider-boringssl") //same as openssl
//include("cryptography-provider-wolfcrypto") //same as openssl
//include("cryptography-provider-tink") //is it needed?

//future features:
// - JWK/JWT support (JOSE)
// - ASN.1/X.509/DER/PEM support (via kx.serialization)

//need:
// - BigInt
// - some new IO
// - auto provider API - not really needed for now
// - C API wrapper
