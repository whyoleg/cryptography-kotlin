plugins {
    `kotlin-dsl`
}

dependencies {
    implementation(kotlin("gradle-plugin"))
}

kotlin {
    jvmToolchain(8)
}
