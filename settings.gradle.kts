enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }

    versionCatalogs {
        create("libs") {
            from(files("libs.versions.toml"))
        }
    }
}

//decide on dependencies:
// * need some IO or use basic VIO
// * need BigInt(f.e. for RSA) implementation
// * need Instant(f.e. for JWT) from kx.datetime
// * need Json(f.e. for JWK/JWT) from kx.serialization
// * DER encoding also can use kx.serialization

//external libraries, are those, which should be later extracted to separate projects/artifacts not related to cryptography at all

//super minimal buffer view api over ByteArray and platform specific implementations
//TODO: replace with NEW ktor-io if released soon
include("external:vio") //deps: no
//super minimal biginteger implementation to support string/arrays of bytes as big integers representation
include("external:bignumber") //deps: no
//super minimal mpp provider api (kotlin provider interface)
//include("external:kpi") //deps: no
//pem and der encoding
//include("external:asn1") //deps: kx.serialization
//include("external:asn1-cryptography") //deps: asn1 (cryptography primitives, per pkcs)
//jwt, jwk, etc. TODO: decide on name
//include("external:jose") //deps: kx.serialization, kx.datetime

//contains common properties/builders
include("cryptography-core") //deps: vio, bn

//default algorithms are those, which supported by default on ALL platforms: RSA(OAEP), AES(CBC, CTR, CBC), HMAC, ECDSA etc
//default - all algorithms that are supported in WebCrypto API
//TODO: decide on name and decide on algorithms providability
//let's leave it for now just `algorithms`
include("cryptography-algorithms") //deps: core

//TODO: move algorithms out of cryptography-core
//include("cryptography-tests")

//try to use openssl at all parts

//Part 1 JVM + JS:
//include("cryptography-providers:cryptography-provider-jce") //jvm only
//include("cryptography-providers:cryptography-provider-webcrypto") //js only
//include("cryptography-providers:cryptography-provider-nodejs") //nodejs only

//Part 2 Native:
//include("cryptography-provider-cng") //mingw only
//include("cryptography-provider-corecrypto") //darwin only

//Part 3 Openssl:
//include("cryptography-provider-openssl-dynamic") //native desktop only, jvm(not android), nodejs (start with native only)
//include("cryptography-provider-openssl-static") //all (start with native descktop only)
//include("cryptography-provider-openssl3-dynamic") //same as openssl
//include("cryptography-provider-openssl3-static") //same as openssl

//Part X
//TODO: are those needed at all?
//include("cryptography-provider-bc") //jvm only
//include("cryptography-provider-wolfcrypto") //all - same as openssl
//include("cryptography-provider-boringssl") //all - same as openssl
//include("cryptography-provider-tink") //is it needed?
//include("cryptography-provider-aws") //remote AWS KMS provider
//include("cryptography-provider-gcp") //remote GCP KMS provider

/*
    encryption/decryption: AES(CTR, CBC, GCM) +, RSA(OAEP)
    hash: SHA(1, 2, 3) +, SHAKE(128, 256) +
    mac: HMAC(ANY HASH) +, CMAC(AES-CBC) +, GMAC(AES-GCM) +
    sing/verify: RSA(SSA, PSS), ECDSA
    key wrap/unwrap: AES(all + KW), RSA(OAEP)
    derive key: ECDH, HKDF, PBKDF2
    importing key formats: RAW, JWK, PKCS-XXX
    JWT
    certificates (x509)
    decide on random
    key store
    TODO: decide on how to load algorithms -
     dynamic or static,
     cause even using RSA(OAEP) for encryption,
     can be not supported using it for singing
    TODO: does key usages needed?
 */