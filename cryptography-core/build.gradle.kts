plugins {
    id("buildx-multiplatform-library")
    id("buildx-target-all")
}

description = "cryptography-kotlin core API"

kotlin {
    sourceSets {
        commonMain {
            dependencies {
                api(projects.cryptographyRandom)
            }
        }
    }
}
