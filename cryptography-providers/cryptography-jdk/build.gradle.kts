plugins {
    id("buildx-multiplatform")
}

kotlin {
    jvm()

    sourceSets {
        all {
            languageSettings.optIn("dev.whyoleg.cryptography.operations.ProviderApi")
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
