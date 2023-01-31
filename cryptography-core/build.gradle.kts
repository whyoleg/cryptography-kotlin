plugins {
    id("buildx-multiplatform-library")
    id("org.jetbrains.kotlinx.binary-compatibility-validator")
    id("org.jetbrains.kotlinx.kover")
    id("org.jetbrains.dokka")
}

kotlin {
    allTargets()
    sourceSets {
        commonMain {
            dependencies {
                api(projects.cryptographyRandom)
            }
        }
    }
}
