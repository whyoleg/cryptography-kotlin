/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.targets.js.nodejs.*
import org.jetbrains.kotlin.gradle.targets.js.npm.*
import org.jetbrains.kotlin.gradle.targets.wasm.nodejs.*
import org.jetbrains.kotlin.gradle.targets.wasm.npm.*

plugins {
    alias(libs.plugins.kotlin.dokka)

    alias(libs.plugins.android.kotlin.multiplatform.library) apply false
    alias(libs.plugins.kotlin.multiplatform) apply false
    alias(libs.plugins.kotlin.plugin.serialization) apply false

    id("ckbuild.use-openssl")
}

Projects.validateProjectTags(project)

// ignore package lock
plugins.withType<NodeJsRootPlugin> {
    extensions.configure<NpmExtension> {
        lockFileDirectory.set(layout.buildDirectory.dir("kotlin-js-store/js"))
        packageLockMismatchReport.set(LockFileMismatchReport.NONE)
    }
}
plugins.withType<WasmNodeJsRootPlugin> {
    extensions.configure<WasmNpmExtension> {
        lockFileDirectory.set(layout.buildDirectory.dir("kotlin-js-store/wasm"))
        packageLockMismatchReport.set(LockFileMismatchReport.NONE)
    }
}

dokka {
    setupHomepageLink()
}

dependencies {
    Projects.libraries.forEach {
        dokka(project(":$it"))
    }
}

tasks.dokkaGeneratePublicationHtml {
    outputDirectory.set(file("docs/api"))
}

tasks.register<Copy>("mkdocsCopy") {
    into(rootDir.resolve("docs"))
    from("CHANGELOG.md")
}

tasks.register<Exec>("mkdocsBuild") {
    dependsOn(tasks.dokkaGeneratePublicationHtml)
    dependsOn(tasks.named("mkdocsCopy"))
    commandLine("mkdocs", "build", "--clean", "--strict")
}
