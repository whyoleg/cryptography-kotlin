plugins {
    id("buildx-multiplatform")
}

kotlin {
    macosX64()
    macosArm64()

    sourceSets {
        all {
            languageSettings.optIn("dev.whyoleg.cryptography.provider.CryptographyProviderApi")
            languageSettings.optIn("dev.whyoleg.cryptography.algorithms.InsecureAlgorithm")
        }
        val commonMain by getting {
            dependencies {
                api(projects.cryptographyCore)
                api(projects.cryptographyRandom)
            }
        }
    }
}
