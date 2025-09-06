import ckbuild.*

/*
 * Split WebCrypto browser tests: core digests + KDF + basic provider checks
 */

plugins {
    id("ckbuild.multiplatform-library")
    id("ckbuild.multiplatform-provider-tests")
}

description = "cryptography-kotlin WebCrypto provider tests (core)"

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
    testClasses.set(
        listOf(
            "DefaultProviderTest",
            "SupportedAlgorithmsTest",

            "Pbkdf2CompatibilityTest",
            "HkdfCompatibilityTest",
            "HkdfTestvectorsTest",

            "DigestTest",
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
        )
    )
}
