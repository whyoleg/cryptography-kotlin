plugins {
    `kotlin-dsl`
}

dependencies {
    implementation(buildLibs.build.kotlin)
}

kotlin {
    jvmToolchain {
        this as JavaToolchainSpec
        languageVersion.set(JavaLanguageVersion.of(8))
    }
}
