/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild.tests

import org.gradle.api.*
import org.gradle.api.file.*
import org.gradle.api.provider.*
import org.gradle.api.tasks.*

abstract class GenerateProviderTestsTask : DefaultTask() {
    @get:Input
    abstract val packageName: Property<String>

    @get:Input
    abstract val imports: ListProperty<String>

    @get:Input
    abstract val testClasses: ListProperty<String>

    @get:Input
    abstract val providerInitializers: MapProperty<String, String>

    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty

    @TaskAction
    fun generateTests() {
        val outputDirectory = outputDirectory.get().asFile

        check(outputDirectory.deleteRecursively()) { "Failed to cleanup files" }
        check(outputDirectory.mkdirs()) { "Failed to create directories" }

        val classes = testClasses.get()
        providerInitializers.get().forEach { (classifier, providerInitialization) ->
            outputDirectory.resolve("${classifier}_tests.kt").writeText(
                testsFileContent(
                    packageName = packageName.get(),
                    imports = imports.get(),
                    testClasses = classes,
                    providerClassifier = classifier,
                    providerInitialization = providerInitialization
                )
            )
        }
    }

    private fun testsFileContent(
        packageName: String,
        imports: List<String>,
        testClasses: List<String>,
        providerClassifier: String,
        providerInitialization: String,
    ): String = buildString {
        appendLine("@file:Suppress(\"ClassName\")").appendLine()
        append("package ").appendLine(packageName).appendLine()

        (defaultImports + imports).forEach { append("import ").appendLine(it) }
        appendLine()

        appendLine("private val CRYPTOGRAPHY_PROVIDER = $providerInitialization").appendLine()

        testClasses.forEach { testClassName ->
            appendLine("class ${providerClassifier}_$testClassName : $testClassName(CRYPTOGRAPHY_PROVIDER)")
        }
        appendLine()
    }

    private companion object {
        private val defaultImports = listOf(
            "dev.whyoleg.cryptography.*",
            "dev.whyoleg.cryptography.providers.tests.compatibility.*",
            "dev.whyoleg.cryptography.providers.tests.default.*",
            "dev.whyoleg.cryptography.providers.tests.testvectors.*",
        )
    }
}
