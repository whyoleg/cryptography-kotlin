import org.jetbrains.kotlin.gradle.plugin.mpp.*

plugins {
    id("buildx-multiplatform-library")
}

kotlin {
    allTargets()

    sharedSourceSet("native") { it is KotlinNativeTarget }
    sourceSets {
        commonMain {
            dependencies {
                api(projects.cryptographyIo)
                api(projects.cryptographyRandom)
            }
        }
    }
}
