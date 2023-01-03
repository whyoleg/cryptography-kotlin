plugins {
    id("buildx-multiplatform")
    alias(libs.plugins.kotlin.serialization)
}

kotlin {
    jvm()
    js {
        nodejs()
    }
    linuxX64()
    macosX64()
    macosArm64()
    mingwX64()

    sourceSets {
        commonMain {
            dependencies {
                api(projects.cryptographyIo)
                api(libs.kotlinx.serialization.protobuf)
            }
        }
    }
}
