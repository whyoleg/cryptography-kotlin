import ckbuild.*

/*
 * Split WebCrypto browser tests: AES modes and CMAC
 */

plugins {
    id("ckbuild.multiplatform-library")
    id("ckbuild.multiplatform-provider-tests")
}

description = "cryptography-kotlin WebCrypto provider tests (AES)"

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
            "AesCbcTest",
            "AesCbcCompatibilityTest",
            "AesCmacTest",
            "AesCmacCompatibilityTest",
            "AesCmacTestvectorsTest",
            "AesCtrTest",
            "AesCtrCompatibilityTest",
            "AesEcbCompatibilityTest",
            "AesGcmTest",
            "AesGcmCompatibilityTest",
        )
    )
}
