plugins {
    id("buildx-multiplatform")
}

kotlin {
    js {
        browser()
        nodejs()
    }

    sourceSets {
        all {
            languageSettings.optIn("dev.whyoleg.cryptography.provider.CryptographyProviderApi")
            languageSettings.optIn("dev.whyoleg.cryptography.algorithms.InsecureAlgorithm")
        }
        val jsMain by getting {
            dependencies {
                api(projects.cryptographyCore)
                api(projects.cryptographyRandom)
            }
        }
    }
}
