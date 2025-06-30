/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    id("org.jetbrains.dokka")
}

dokka {
    dokkaPublications.configureEach {
        // we don't suppress inherited members explicitly as without it classes like RSA.OAEP don't show functions like keyGenerator
        suppressInheritedMembers = false
        failOnWarning = true
    }
    dokkaSourceSets.configureEach {
        includes.from(rootDir.resolve("dokka/modules.md"))
        reportUndocumented = false // set true later
        skipDeprecated = true
        sourceLink {
            localDirectory = rootDir
            remoteUrl("https://github.com/whyoleg/cryptography-kotlin/tree/$version/")
        }
    }
}
