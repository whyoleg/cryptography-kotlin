import ckbuild.*

/*
 * Split WebCrypto browser tests: RSA
 */

plugins {
    id("ckbuild.multiplatform-library")
    id("ckbuild.multiplatform-provider-tests")
}

description = "cryptography-kotlin WebCrypto provider tests (RSA)"

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
            "RsaOaepTest",
            "RsaOaepCompatibilityTest",
            "RsaPkcs1Test",
            "RsaPkcs1CompatibilityTest",
            "RsaPkcs1EsCompatibilityTest",
            "RsaPssTest",
            "RsaPssCompatibilityTest",
            "RsaRawCompatibilityTest",
        )
    )
}
