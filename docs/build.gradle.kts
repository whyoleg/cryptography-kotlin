/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*

plugins {
    id("org.jetbrains.dokka")
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
    outputDirectory.set(layout.projectDirectory.dir("api"))
}

tasks.register<Copy>("mkdocsCopy") {
    into(layout.projectDirectory)
    from(rootDir.resolve("CHANGELOG.md"))
}

tasks.register<Exec>("mkdocsBuild") {
    workingDir = layout.projectDirectory.asFile
    dependsOn(tasks.dokkaGeneratePublicationHtml)
    dependsOn(tasks.named("mkdocsCopy"))
    commandLine("mkdocs", "build", "--clean", "--strict")
}
