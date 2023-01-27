plugins {
    id("buildx-multiplatform")
    `maven-publish`
}

kotlin {
    explicitApi()

    sourceSets {
        commonMain {
            dependencies {
                api(platform(project(":cryptography-bom")))
            }
        }
    }
}
