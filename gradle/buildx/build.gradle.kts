plugins {
    `kotlin-dsl`
}

dependencies {
    implementation(libs.build.kotlin)
}

kotlin {
    jvmToolchain(8)
}
