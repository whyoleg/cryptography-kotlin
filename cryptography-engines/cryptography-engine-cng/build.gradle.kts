plugins {
    `multiplatform-base`
}

kotlin {
    mingwX64()

    sourceSets {
        val commonMain by getting {
            dependencies {
                api(projects.cryptographyCore)
            }
        }
    }
}
