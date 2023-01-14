import org.jetbrains.kotlin.gradle.plugin.*

plugins {
    id("buildx-multiplatform-library")
}

kotlin {
    allTargets()

    sharedSourceSet("nonJvm") { it.platformType != KotlinPlatformType.jvm && it.platformType != KotlinPlatformType.common }
}
