plugins {
    id("buildx-multiplatform-library")
}

kotlin {
    jvm()

    sourceSets {
        all {
            languageSettings.optIn("dev.whyoleg.cryptography.provider.CryptographyProviderApi")
            languageSettings.optIn("dev.whyoleg.cryptography.algorithms.InsecureAlgorithm")
        }
        val jvmMain by getting {
            dependencies {
                api(projects.cryptographyCore)
                api(projects.cryptographyRandom)
            }
        }
    }
}
