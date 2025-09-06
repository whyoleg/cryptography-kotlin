import ckbuild.*

/*
 * Split WebCrypto browser tests: HMAC
 */

plugins {
    id("ckbuild.multiplatform-library")
    id("ckbuild.multiplatform-provider-tests")
}

description = "cryptography-kotlin WebCrypto provider tests (MAC)"

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
            "HmacTest",
            "HmacCompatibilityTest",
            "HmacTestvectorsTest",
        )
    )
}
