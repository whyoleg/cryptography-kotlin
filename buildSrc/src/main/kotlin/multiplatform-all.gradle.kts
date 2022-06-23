import org.jetbrains.kotlin.gradle.plugin.mpp.*

plugins {
    id("multiplatform-base")
}

kotlin {
    jvm {
        compilations.all {
            kotlinOptions {
                this.freeCompilerArgs += "-Xjdk-release=1.8" //TODO
            }
        }
    }
    js {
        browser()
        nodejs()
    }

    macosX64()
    macosArm64()
    linuxX64()
    mingwX64()

    sourceSets {
        val commonMain by getting
        val commonTest by getting

        val nativeMain by creating {
            dependsOn(commonMain)
        }
        val nativeTest by creating {
            dependsOn(nativeMain)
            dependsOn(commonTest)
        }

        targets.all {
            if (this is KotlinNativeTarget) {
                getByName("${name}Main").dependsOn(nativeMain)
                getByName("${name}Test").dependsOn(nativeTest)
            }
        }
    }
}
