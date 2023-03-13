import org.jetbrains.kotlin.gradle.plugin.*

plugins {
    id("buildx-multiplatform")
    id("buildx-target-js")
    id("buildx-target-jvm")
    id("buildx-target-native-all")
}

kotlin {
    sharedSourceSet("nonJvm") { it.platformType != KotlinPlatformType.jvm && it.platformType != KotlinPlatformType.common }
}
