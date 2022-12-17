plugins {
    id("buildx-multiplatform")
}

kotlin {
    js {
        browser()
        nodejs()
    }

    sourceSets {
        val jsMain by getting {
            dependencies {
                api(projects.cryptographyAlgorithms)
            }
        }
    }
}
