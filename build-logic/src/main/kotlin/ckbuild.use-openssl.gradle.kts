/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
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
    configureOpenssl("v3_1", "3.1.7", "3.1.7_1", service.v3_1)
    configureOpenssl("v3_2", "3.2.3", "3.2.3_1", service.v3_2)
    configureOpenssl("v3_3", "3.3.2", "3.3.2_1", service.v3_3)
}
