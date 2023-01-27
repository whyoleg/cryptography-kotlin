plugins {
    id("buildx-multiplatform-library")
}

kotlin {
    desktopTargets()

    sourceSets {
        commonMain {
            dependencies {
                api(projects.cryptographyProviders.cryptographyOpenssl3)
            }
        }
    }
}
