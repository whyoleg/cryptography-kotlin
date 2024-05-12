/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.gradle.targets.js.nodejs.*
import org.jetbrains.kotlin.gradle.targets.js.npm.*

plugins {
    alias(libs.plugins.kotlin.dokka)

    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.multiplatform) apply false
    alias(libs.plugins.kotlin.plugin.serialization) apply false
}

plugins.withType<NodeJsRootPlugin> {
    // ignore package lock
    extensions.configure<NpmExtension> {
        lockFileDirectory.set(layout.buildDirectory.dir("kotlin-js-store"))
        packageLockMismatchReport.set(LockFileMismatchReport.NONE)
    }
}

tasks.dokkaHtmlMultiModule {
    outputDirectory.set(file("docs/api"))
}

tasks.register<Copy>("mkdocsCopy") {
    into(rootDir.resolve("docs"))
    from("README.md")
    from("CHANGELOG.md")
}

tasks.register<Exec>("mkdocsBuild") {
    dependsOn(tasks.dokkaHtmlMultiModule)
    dependsOn(tasks.named("mkdocsCopy"))
    dependsOn(subprojects.mapNotNull { it.tasks.findByName("mkdocsCopy") })
    commandLine("mkdocs", "build", "--clean", "--strict")
}
