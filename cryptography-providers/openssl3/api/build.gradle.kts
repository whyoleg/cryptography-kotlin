plugins {
    id("buildx-multiplatform-provider")
    id("org.jetbrains.dokka")
}

description = "cryptography-kotlin OpenSSL3 provider (API)"

kotlin {
    appleTargets()
    desktopTargets()

    sourceSets {
        commonMain {
            dependencies {
                implementation(kcwrapperLibs.libraries.libcrypto3.api)
            }
        }
    }
}
