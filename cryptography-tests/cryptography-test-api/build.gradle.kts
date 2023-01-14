plugins {
    id("buildx-multiplatform")
    alias(libs.plugins.kotlin.serialization)
}

kotlin {
    allTargets()

    sourceSets {
        commonMain {
            dependencies {
                api(libs.kotlinx.serialization.protobuf)
            }
        }
    }
}
