/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import ckbuild.docs.*

plugins {
    id("ckbuild.dokka")
}

dependencies {
    Projects.documented.forEach {
        dokka(project(":$it"))
    }
}

tasks.dokkaGeneratePublicationHtml {
    outputDirectory.set(file("docs/api"))
}

val generateAlgorithmTables = tasks.register<GenerateAlgorithmTablesTask>("generateAlgorithmTables") {
    outputDirectory.set(file("docs/snippets/operations"))
}

tasks.register<Copy>("mkdocsPrepare") {
    dependsOn(generateAlgorithmTables, tasks.dokkaGeneratePublicationHtml)
    destinationDir = file("docs")

    from("CHANGELOG.md") {
        rename { "changelog.md" }
    }
}
