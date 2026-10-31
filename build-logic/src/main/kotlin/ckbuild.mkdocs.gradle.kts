/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import ckbuild.docs.*
import ckbuild.providertests.*

plugins {
    id("ckbuild.dokka")
    id("ckbuild.test-limitations")
}

dependencies {
    documentedLibrariesProjectNames().forEach {
        dokka(project(":$it"))
    }
}

tasks.dokkaGeneratePublicationHtml {
    outputDirectory.set(file("docs/api"))
}

val generateAlgorithmTables = tasks.register<GenerateAlgorithmTablesTask>("generateAlgorithmTables") {
    mustRunAfter(tasks.named("updateTestLimitations"))
    limitationsFile.set(testLimitationsFile())
    outputDirectory.set(file("docs/snippets/operations"))
}

val updateReadmeAlgorithmTable = tasks.register<UpdateReadmeAlgorithmTableTask>("updateReadmeAlgorithmTable") {
    readmeFile.set(file("README.md"))
}

tasks.register<Copy>("mkdocsPrepare") {
    dependsOn(generateAlgorithmTables, tasks.dokkaGeneratePublicationHtml)
    destinationDir = file("docs")

    from("CHANGELOG.md") {
        rename { "changelog.md" }
    }
}
