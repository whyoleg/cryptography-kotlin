plugins {
    id("buildx-multiplatform")
}

kotlin {
    jvm()

    sourceSets {
        val jvmMain by getting {
            dependencies {
                api(projects.cryptographyAlgorithms)
            }
        }
    }
}
