plugins {
    id("buildx-multiplatform")
}

kotlin {
    macosX64()
    macosArm64()

    sourceSets {
        val commonMain by getting {
            dependencies {
                api(projects.cryptographyAlgorithms)
            }
        }
    }
}
