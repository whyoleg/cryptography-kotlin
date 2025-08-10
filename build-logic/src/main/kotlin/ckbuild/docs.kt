package ckbuild

import org.jetbrains.dokka.gradle.*

fun DokkaExtension.registerKotlinxIoExternalDocumentation() {
    dokkaSourceSets.configureEach {
        externalDocumentationLinks.register("kotlinx-io") {
            url("https://kotlinlang.org/api/kotlinx-io/")
        }
    }
}


fun DokkaExtension.includeCommonDocs() {
    dokkaSourceSets.configureEach {
        if (name.endsWith("Main")) {
            // TODO: dokka requires for `includes` files to be present...
            //  otherwise we could use `includes.from("src/${name}Docs/module.md")`
            includes.from("src/commonDocs/module.md")
        }
    }
}
