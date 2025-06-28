/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    id("org.jetbrains.dokka")
}

val readme = file("README.md")

tasks.register<Copy>("mkdocsCopy") {
    // store into variables to work around configuration cache issues
    val moduleName = dokka.moduleName
    val readme = readme

    onlyIf { readme.exists() }
    if (readme.exists()) from(readme)
    into(rootDir.resolve("docs/modules"))
    rename { "${moduleName.get()}.md" }
}

dokka {
    dokkaPublications.configureEach {
        // we don't suppress inherited members explicitly as without it classes like RSA.OAEP don't show functions like keyGenerator
        suppressInheritedMembers = false
        failOnWarning = true
    }
    dokkaSourceSets.configureEach {
        if (readme.exists()) includes.from(readme)
        reportUndocumented = false // set true later
        skipDeprecated = true
        sourceLink {
            localDirectory = rootDir
            remoteUrl("https://github.com/whyoleg/cryptography-kotlin/tree/$version/")
        }
    }
}
