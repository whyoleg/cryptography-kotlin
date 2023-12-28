/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.gradle.targets.js.yarn.*

plugins {
    alias(libs.plugins.kotlin.dokka)

    alias(libs.plugins.android.library) apply false
    alias(kotlinLibs.plugins.multiplatform) apply false
    alias(kotlinLibs.plugins.serialization) apply false
}

plugins.withType<YarnPlugin> {
    yarn.apply {
        lockFileDirectory = rootDir.resolve("gradle/js")
        yarnLockMismatchReport = YarnLockMismatchReport.NONE
    }
}

tasks.dokkaHtmlMultiModule {
    outputDirectory.set(file("docs/api"))
}

tasks.register<Exec>("mkdocsBuild") {
    dependsOn(tasks.dokkaHtmlMultiModule)
    dependsOn(subprojects.mapNotNull { it.tasks.findByName("mkdocsCopy") })
    commandLine("mkdocs", "build", "--clean", "--strict")
}

val skipTest = providers.gradleProperty("skip.test").map(String::toBoolean).getOrElse(false)
val skipLink = providers.gradleProperty("skip.link").map(String::toBoolean).getOrElse(false)

subprojects {
    if (skipTest) tasks.matching { it.name.endsWith("test", ignoreCase = true) }.configureEach { onlyIf { false } }
    if (skipLink) tasks.matching { it.name.startsWith("link", ignoreCase = true) }.configureEach { onlyIf { false } }
}
