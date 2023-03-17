/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

/**
 * run to check for dependencies:
 *  ./gradlew :dependencyUpdates --init-script gradle/libs.updates.gradle.kts --no-configure-on-demand
 */

initscript {
    repositories {
        gradlePluginPortal()
    }
    dependencies {
        classpath("com.github.ben-manes:gradle-versions-plugin:+")
    }
}

allprojects {
    println("Project: $name / ${rootProject.name}")
    apply<com.github.benmanes.gradle.versions.VersionsPlugin>()

    // for root project add dependency on included builds
    if (name == "cryptography-kotlin") tasks.named("dependencyUpdates") {
        gradle.includedBuilds.forEach {
            dependsOn(it.task(":dependencyUpdates"))
        }
    }
}
