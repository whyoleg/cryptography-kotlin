/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package openssl

import de.undercouch.gradle.tasks.download.*
import org.gradle.api.*
import org.gradle.api.tasks.*
import org.gradle.kotlin.dsl.*

class OpensslRootPlugin : Plugin<Project> {
    override fun apply(target: Project): Unit = target.run {
        check(this == rootProject)

        val downloadOpenssl by tasks.registering(Download::class) {
            src("https://github.com/whyoleg/openssl-builds/releases/download/3.0.8-build-2/openssl3-all.zip")
            onlyIfModified(true)
            dest(layout.buildDirectory.file("openssl/prebuilt.zip"))
        }

        tasks.register(PREPARE_OPENSSL_TASK_NAME, Sync::class) {
            from(downloadOpenssl.map { zipTree(it.outputFiles.single()) })
            into(layout.buildDirectory.dir("openssl/prebuilt"))
        }
    }

    companion object {
        val PREPARE_OPENSSL_TASK_NAME = "prepareOpenssl"
    }
}
