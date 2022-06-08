plugins {
    `multiplatform-all`
}

kotlin {
    sourceSets {
        commonMain {
            dependencies {
                api(projects.cryptographyApi)
            }
        }
    }
}
