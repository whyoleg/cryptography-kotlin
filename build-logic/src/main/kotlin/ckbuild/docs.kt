package ckbuild

import org.jetbrains.dokka.gradle.*

fun DokkaExtension.registerKotlinxIoExternalDocumentation() {
    dokkaSourceSets.configureEach {
        externalDocumentationLinks.register("kotlinx-io") {
            url("https://kotlinlang.org/api/kotlinx-io/")
        }
    }
}
