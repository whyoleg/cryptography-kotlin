plugins {
    id("buildx-multiplatform-library")
}

kotlin {
    sourceSets {
        all {
            languageSettings.optIn("dev.whyoleg.cryptography.provider.CryptographyProviderApi")
            languageSettings.optIn("dev.whyoleg.cryptography.algorithms.InsecureAlgorithm")
        }
        commonMain {
            dependencies {
                api(project(":cryptography-core"))
            }
        }
    }
}
