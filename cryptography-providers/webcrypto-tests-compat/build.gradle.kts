import ckbuild.*

/*
 * Split WebCrypto browser tests: Compatibility-only suites
 */

plugins {
    id("ckbuild.multiplatform-library")
    id("ckbuild.multiplatform-provider-tests")
}

description = "cryptography-kotlin WebCrypto provider tests (compatibility)"

@OptIn(org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi::class)
kotlin {
    webTargets()
    sourceSets.commonTest.dependencies {
        implementation(projects.cryptographyProviderWebcrypto)
    }
}

providerTests {
    packageName.set("dev.whyoleg.cryptography.providers.webcrypto")
    providerInitializers.put("WebCrypto", "CryptographyProvider.WebCrypto")
    // Only Compatibility suites across algorithms (exclude testvectors & standalone non-compat tests)
    testClasses.set(
        listOf(
            "Pbkdf2CompatibilityTest",
            "HkdfCompatibilityTest",

            "Md5CompatibilityTest",
            "Sha1CompatibilityTest",
            "Sha224CompatibilityTest",
            "Sha256CompatibilityTest",
            "Sha384CompatibilityTest",
            "Sha512CompatibilityTest",
            "Sha3B224CompatibilityTest",
            "Sha3B256CompatibilityTest",
            "Sha3B384CompatibilityTest",
            "Sha3B512CompatibilityTest",
            "Ripemd160CompatibilityTest",

            "AesCbcCompatibilityTest",
            "AesCmacCompatibilityTest",
            "AesCtrCompatibilityTest",
            "AesEcbCompatibilityTest",
            "AesGcmCompatibilityTest",

            "HmacCompatibilityTest",

            "EcdsaCompatibilityTest",
            "EcdhCompatibilityTest",

            "RsaOaepCompatibilityTest",
            "RsaPkcs1CompatibilityTest",
            "RsaPkcs1EsCompatibilityTest",
            "RsaPssCompatibilityTest",
            "RsaRawCompatibilityTest",
        )
    )
}
