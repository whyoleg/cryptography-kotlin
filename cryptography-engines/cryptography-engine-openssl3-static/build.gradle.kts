plugins {
    `multiplatform-base`
}

kotlin {
    macosX64()
    macosArm64()
    linuxX64()
    mingwX64()

    sourceSets {
        val commonMain by getting {
            dependencies {
                api(projects.cryptographyCore)
            }
        }
    }
}
