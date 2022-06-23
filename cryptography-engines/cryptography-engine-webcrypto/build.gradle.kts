plugins {
    `multiplatform-base`
}

kotlin {
    js {
        browser()
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
