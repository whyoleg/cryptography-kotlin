import org.jetbrains.kotlin.gradle.targets.native.tasks.*

plugins {
    id("buildx-multiplatform")
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
                api(projects.cryptographyApi)
            }
        }
    }
}
