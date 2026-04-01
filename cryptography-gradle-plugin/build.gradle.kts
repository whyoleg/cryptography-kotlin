/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    id("ckbuild.gradle-plugin")
}

description = "cryptography-kotlin Gradle plugin"

gradlePlugin {
    plugins.register("dev.whyoleg.cryptography") {
        implementationClass = "dev.whyoleg.cryptography.gradle.CryptographyPlugin"
    }
}

val devArtifactsDirectory = layout.buildDirectory.dir("maven-dev-artifacts")

publishing.repositories.maven(devArtifactsDirectory) { name = "dev" }

tasks.withType<Test>().configureEach {
    dependsOn(tasks.named("publishAllPublicationsToDevRepository"))

    inputs
        .files(devArtifactsDirectory.get().asFileTree.matching { include("**/*.module") })
        .withPathSensitivity(PathSensitivity.RELATIVE)
        .withPropertyName("devArtifacts")

    systemProperty("cktests.dev-artifacts-directories", devArtifactsDirectory.get().asFile.canonicalPath)
    systemProperty("cktests.dev-artifacts-version", project.version.toString())
}
