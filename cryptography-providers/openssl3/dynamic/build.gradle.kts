plugins {
    id("buildx-multiplatform-library")
}

description = "cryptography-kotlin OpenSSL3 provider (dynamic linking)"

kotlin {
    desktopTargets()

    sourceSets {
        commonMain {
            dependencies {
                api(projects.cryptographyProviders.cryptographyOpenssl3.cryptographyOpenssl3Api)
                implementation(kcwrapperLibs.libraries.libcrypto3.dynamic)
            }
        }
    }
}
