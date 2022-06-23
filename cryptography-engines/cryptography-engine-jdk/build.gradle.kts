plugins {
    `multiplatform-base`
}

kotlin {
    jvm()

    sourceSets {
        val jvmMain by getting {
            dependencies {
                api(projects.cryptographyCore)
            }
        }
    }
}
