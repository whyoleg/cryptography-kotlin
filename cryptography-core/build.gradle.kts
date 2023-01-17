plugins {
    id("buildx-multiplatform-library")
}

kotlin {
    allTargets()
    sourceSets {
        commonMain {
            dependencies {
                api(projects.cryptographyIo)
                api(projects.cryptographyRandom)
            }
        }
    }
}
