plugins {
    `multiplatform-base`
}

kotlin {
    js {
        nodejs()
    }

    sourceSets {
        val jsMain by getting {
            dependencies {
                api(projects.cryptographyCore)
            }
        }
    }
}
