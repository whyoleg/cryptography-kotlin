/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.documentation.*
import org.jetbrains.dokka.gradle.*
import java.net.*

plugins {
    id("org.jetbrains.dokka")
}

val documentation = extensions.create<DocumentationExtension>("documentation").apply {
    moduleName.convention(project.name)
    includes.set("README.md")
}

tasks.register<Copy>("mkdocsCopy") {
    onlyIf { documentation.includes.isPresent }
    if (documentation.includes.isPresent) from(documentation.includes)
    into(rootDir.resolve("docs/modules"))
    rename { "${documentation.moduleName.get()}.md" }
}

tasks.withType<DokkaTaskPartial>().configureEach {
    moduleName.set(documentation.moduleName)
    suppressInheritedMembers.set(true)
    failOnWarning.set(true)
    dokkaSourceSets.configureEach {
        if (documentation.includes.isPresent) includes.from(documentation.includes)
        reportUndocumented.set(false) // set true later
        sourceLink {
            localDirectory.set(rootDir)
            remoteUrl.set(URI("https://github.com/whyoleg/cryptography-kotlin/tree/main/").toURL())
            remoteLineSuffix.set("#L")
        }
    }
}
