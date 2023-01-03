import org.jetbrains.kotlin.gradle.plugin.*

plugins {
    id("buildx-multiplatform")
}

kotlin {
    jvm()
    js {
        browser()
        nodejs()
    }
    linuxX64()
    macosX64()
    macosArm64()
    mingwX64()

    sourceSets {
        val nonJvmMain by creating {
            dependsOn(commonMain.get())
        }
        val nonJvmTest by creating {
            dependsOn(commonTest.get())
        }

        targets.all {
            if (platformType != KotlinPlatformType.jvm && platformType != KotlinPlatformType.common) {
                getByName("${name}Main").dependsOn(nonJvmMain)
                getByName("${name}Test").dependsOn(nonJvmTest)
            }
        }
    }
}
