import org.jetbrains.kotlin.gradle.plugin.mpp.*

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

    targets.all {
        if (this !is KotlinNativeTarget) return@all
        val main by compilations.getting {
            val linkerOpts by cinterops.creating {
                defFile("linkerOpts.def")
            }
        }
    }
}
