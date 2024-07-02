/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
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
    abstract val providerInitializers: MapProperty<String, String>

    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty

    @TaskAction
    fun generateTests() {
        val outputDirectory = outputDirectory.get().asFile

        check(outputDirectory.deleteRecursively()) { "Failed to cleanup files" }
        check(outputDirectory.mkdirs()) { "Failed to create directories" }

        providerInitializers.get().forEach { (classifier, providerInitialization) ->
            outputDirectory.resolve("${classifier}_tests.kt").writeText(
                testsFileContent(
                    packageName = packageName.get(),
                    imports = imports.get(),
                    providerClassifier = classifier,
                    providerInitialization = providerInitialization
                )
            )
        }
    }

    private fun testsFileContent(
        packageName: String,
        imports: List<String>,
        providerClassifier: String,
        providerInitialization: String,
    ): String = buildString {
        appendLine("@file:Suppress(\"ClassName\")").appendLine()
        append("package ").appendLine(packageName).appendLine()

        (defaultImports + imports).forEach { append("import ").appendLine(it) }
        appendLine()

        appendLine("private val CRYPTOGRAPHY_PROVIDER = $providerInitialization").appendLine()

        testClasses.forEach {
            val testClassName = it.substringAfterLast(".")
            appendLine("class ${providerClassifier}_$testClassName : $testClassName(CRYPTOGRAPHY_PROVIDER)")
        }
        appendLine()
    }

    private companion object {
        private val defaultImports = listOf(
            "dev.whyoleg.cryptography.*",
            "dev.whyoleg.cryptography.providers.tests.*",
            "dev.whyoleg.cryptography.providers.tests.algorithms.asymmetric.*",
            "dev.whyoleg.cryptography.providers.tests.algorithms.digest.*",
            "dev.whyoleg.cryptography.providers.tests.algorithms.symmetric.*",
        )

        private val testClasses = listOf(
            "dev.whyoleg.cryptography.providers.tests.algorithms.SupportedAlgorithmsTest",

            "dev.whyoleg.cryptography.providers.tests.algorithms.digest.DigestTest",
            "dev.whyoleg.cryptography.providers.tests.algorithms.digest.Md5CompatibilityTest",
            "dev.whyoleg.cryptography.providers.tests.algorithms.digest.Sha1CompatibilityTest",
            "dev.whyoleg.cryptography.providers.tests.algorithms.digest.Sha224CompatibilityTest",
            "dev.whyoleg.cryptography.providers.tests.algorithms.digest.Sha256CompatibilityTest",
            "dev.whyoleg.cryptography.providers.tests.algorithms.digest.Sha384CompatibilityTest",
            "dev.whyoleg.cryptography.providers.tests.algorithms.digest.Sha512CompatibilityTest",
            "dev.whyoleg.cryptography.providers.tests.algorithms.digest.Sha3B224CompatibilityTest",
            "dev.whyoleg.cryptography.providers.tests.algorithms.digest.Sha3B256CompatibilityTest",
            "dev.whyoleg.cryptography.providers.tests.algorithms.digest.Sha3B384CompatibilityTest",
            "dev.whyoleg.cryptography.providers.tests.algorithms.digest.Sha3B512CompatibilityTest",

            "dev.whyoleg.cryptography.providers.tests.algorithms.symmetric.AesCbcTest",
            "dev.whyoleg.cryptography.providers.tests.algorithms.symmetric.AesCbcCompatibilityTest",
            "dev.whyoleg.cryptography.providers.tests.algorithms.symmetric.AesCtrCompatibilityTest",
            "dev.whyoleg.cryptography.providers.tests.algorithms.symmetric.AesEcbCompatibilityTest",
            "dev.whyoleg.cryptography.providers.tests.algorithms.symmetric.AesGcmTest",
            "dev.whyoleg.cryptography.providers.tests.algorithms.symmetric.AesGcmCompatibilityTest",
            "dev.whyoleg.cryptography.providers.tests.algorithms.symmetric.HmacTest",
            "dev.whyoleg.cryptography.providers.tests.algorithms.symmetric.HmacCompatibilityTest",

            "dev.whyoleg.cryptography.providers.tests.algorithms.asymmetric.EcdsaTest",
            "dev.whyoleg.cryptography.providers.tests.algorithms.asymmetric.EcdsaCompatibilityTest",
            "dev.whyoleg.cryptography.providers.tests.algorithms.asymmetric.RsaOaepTest",
            "dev.whyoleg.cryptography.providers.tests.algorithms.asymmetric.RsaOaepCompatibilityTest",
            "dev.whyoleg.cryptography.providers.tests.algorithms.asymmetric.RsaPkcs1Test",
            "dev.whyoleg.cryptography.providers.tests.algorithms.asymmetric.RsaPkcs1CompatibilityTest",
            "dev.whyoleg.cryptography.providers.tests.algorithms.asymmetric.RsaPkcs1EsCompatibilityTest",
            "dev.whyoleg.cryptography.providers.tests.algorithms.asymmetric.RsaPssTest",
            "dev.whyoleg.cryptography.providers.tests.algorithms.asymmetric.RsaPssCompatibilityTest",
            "dev.whyoleg.cryptography.providers.tests.algorithms.asymmetric.RsaRawCompatibilityTest",
        )
    }
}
