import ckbuild.*

/*
 * Split WebCrypto browser tests: EC (EdDSA, XDH, ECDSA/ECDH)
 */

plugins {
    id("ckbuild.multiplatform-library")
    id("ckbuild.multiplatform-provider-tests")
}

description = "cryptography-kotlin WebCrypto provider tests (EC)"

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
            "EcdsaTest",
            "EcdsaCompatibilityTest",
            "EcdhCompatibilityTest",
        )
    )
}
