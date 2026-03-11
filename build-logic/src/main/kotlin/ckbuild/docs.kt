/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild

import org.jetbrains.dokka.gradle.*

fun DokkaExtension.includeCommonDocs() {
    dokkaSourceSets.configureEach {
        if (name.endsWith("Main")) {
            // TODO: dokka requires for `includes` files to be present...
            //  otherwise we could use `includes.from("src/${name}Docs/module.md")`
            includes.from("src/commonDocs/module.md")
        }
    }
}
