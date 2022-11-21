plugins {
    `kotlin-dsl`
}

dependencies {
    implementation(libs.build.kotlin)
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
}
