/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.openssl.*

val service = gradle.sharedServices.registerIfAbsent("OpensslService", OpensslService::class)

extensions.add("openssl", OpensslExtension(service))

if (project == rootProject) {
    val service = service.get()
    fun configureOpenssl(
        classifier: String,
        version: String,
        tag: String,
        property: DirectoryProperty,
    ) {
        val configuration = configurations.create("openssl_$classifier")
        dependencies {
            configuration("ckbuild.dependencies.openssl:openssl-$version:$tag@zip")
        }

        val setupOpenssl = tasks.register<UnzipTask>("setupOpenssl_$classifier") {
            inputFile.set(project.layout.file(provider { configuration.singleFile }))
            outputDirectory.set(temporaryDir)
        }

        property.set(setupOpenssl.map { it.outputDirectory.get() })
    }

    configureOpenssl("v3_0", "3.0.15", "3.0.15_1", service.v3_0)
    configureOpenssl("v3_6", "3.6.0", "3.6.0", service.v3_6)
}
