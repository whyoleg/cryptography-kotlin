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
            val openssl3 by cinterops.creating {
                defFile("cinterop/openssl3.def")
            }
        }
    }
}
