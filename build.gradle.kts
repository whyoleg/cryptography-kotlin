/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.gradle.targets.js.yarn.*

plugins {
    id("build-parameters")

    alias(libs.plugins.kotlin.dokka)

    alias(kotlinLibs.plugins.multiplatform) apply false
    alias(kotlinLibs.plugins.serialization) apply false
}

plugins.withType<YarnPlugin> {
    yarn.apply {
        lockFileDirectory = rootDir.resolve("gradle/js")
        yarnLockMismatchReport = YarnLockMismatchReport.WARNING
        resolution("ua-parser-js", "0.7.33")
    }
}

tasks.dokkaHtmlMultiModule {
    outputDirectory.set(file("docs/api"))
    includes.from("MODULES.md")
}

tasks.register<Copy>("copyForMkDocs") {
    from("README.md")
    into(rootDir.resolve("docs"))
    rename { "index.md" }
}

tasks.register<Exec>("buildMkDocs") {
    dependsOn(tasks.dokkaHtmlMultiModule)
    dependsOn("copyForMkDocs")
    dependsOn(subprojects.mapNotNull { it.tasks.findByName("copyForMkDocs") })
    commandLine("mkdocs", "build", "--clean", "--strict")
}

val skipTest = buildParameters.skip.test
val skipLink = buildParameters.skip.link

subprojects {
    if (skipTest) tasks.matching { it.name.endsWith("test", ignoreCase = true) }.configureEach { onlyIf { false } }
    if (skipLink) tasks.matching { it.name.startsWith("link", ignoreCase = true) }.configureEach { onlyIf { false } }
}
