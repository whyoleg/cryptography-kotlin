plugins {
    id("buildx-multiplatform")
    id("buildx-target-native-all")
}

kotlin {
    sourceSets {
        commonMain {
            dependencies {
                api(kotlin("test"))
                api(projects.cryptographyProviders.cryptographyOpenssl3.cryptographyOpenssl3Api)
            }
        }
    }
}
