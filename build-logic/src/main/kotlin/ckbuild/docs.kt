package ckbuild

import org.gradle.kotlin.dsl.*
import org.jetbrains.dokka.gradle.*
import org.jetbrains.dokka.gradle.engine.plugins.*

fun DokkaExtension.setupHomepageLink() {
    pluginsConfiguration.named<DokkaHtmlPluginParameters>("html") {
        homepageLink.set("https://whyoleg.github.io/cryptography-kotlin")
    }
}

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
