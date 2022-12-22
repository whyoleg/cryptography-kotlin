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

//What is core? may be api?
include("cryptography-core")

//operation / algorithms injection
include("cryptography-provider")

//default operations APIs
// divided in packages per kind of operation (hash, signature, encryption, random, etc)
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


//WIP

//need to support ALL algorithms that are shared between:
// - JDK (jvm/android)
// - JS WebCrypto (js) - only async support, small subset of algorithms
// - CoreCrypto (darwin/iOS)
// - CryptoKit (swift) - at least try to use it and check which algorithms are supported
// - OpenSSL (linux)
// - CNG (windows)
// - Rust Crypto - check on supported algorithms
// + some additional popular algorithms that are supported by JDK/OpenSSL

/** Algorithms examples:
 * - encryption/decryption: AES(CTR, CBC, GCM) +, RSA(OAEP)
 * - hash: SHA(1, 2, 3) +, SHAKE(128, 256) +
 * - mac: HMAC(ANY HASH) +, CMAC(AES-CBC) +, GMAC(AES-GCM) +
 * - sing/verify: RSA(SSA, PSS), ECDSA
 * - key wrap/unwrap: AES(all + KW), RSA(OAEP)
 * - derive key: ECDH, HKDF, PBKDF2
 * - importing key formats: RAW, JWK, PKCS-XXX
 */

//get can be sync and async; primitive can be sync and async


/**
 * TODO
 *  - key / keypair / symmetric(secret) key / asymmetric (private + public) key
 *  - derive key
 *  - key agreement (?)
 *  - key exchange (?)
 *  - keystore/keymanager/keychain/keyring
 *  - import key
 *  - export key
 *  - wrap key
 *  - unwrap key
 *  - key formats
 *  - key usages
 */

//Key format: RAW (Bytes), PEM, DER, JWK, PKCS-12
//Destination: java key store, key chain, file, secure enclave (?)
