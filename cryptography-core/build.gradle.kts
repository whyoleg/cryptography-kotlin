plugins {
    id("buildx-multiplatform-library")
    id("org.jetbrains.kotlinx.binary-compatibility-validator")
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
