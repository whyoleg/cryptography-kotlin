/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild.providertests

import org.gradle.api.*
import org.gradle.api.file.*
import org.gradle.api.provider.*
import org.gradle.api.tasks.*

//@CacheableTask
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

        testClasses.forEach { testClassName ->
            appendLine("class ${providerClassifier}_$testClassName : $testClassName(CRYPTOGRAPHY_PROVIDER)")
        }
        appendLine()
    }

    private companion object {
        private val defaultImports = listOf(
            "dev.whyoleg.cryptography.*",
            "dev.whyoleg.cryptography.tests.*",
            "dev.whyoleg.cryptography.tests.algorithms.*",
            // old tests, while they are not migrated
            "dev.whyoleg.cryptography.providers.tests.compatibility.*",
            "dev.whyoleg.cryptography.providers.tests.default.*",
            "dev.whyoleg.cryptography.providers.tests.testvectors.*",
        )

        private val testClasses = listOf(
            "DefaultProviderTest",
            "Md5AlgorithmTest",
            "Sha1AlgorithmTest",
            "Sha224AlgorithmTest",
            "Sha256AlgorithmTest",
            "Sha384AlgorithmTest",
            "Sha512AlgorithmTest",
            "Sha3B224AlgorithmTest",
            "Sha3B256AlgorithmTest",
            "Sha3B384AlgorithmTest",
            "Sha3B512AlgorithmTest",
            "Ripemd160AlgorithmTest",

            // old tests, while they are not migrated
            "SupportedAlgorithmsTest",
            "Pbkdf2CompatibilityTest",
            "HkdfCompatibilityTest",
            "HkdfTestvectorsTest",
            "AesCbcTest",
            "AesCbcCompatibilityTest",
            "AesCfb8Test",
            "AesCfb8CompatibilityTest",
            "AesCmacTest",
            "AesCmacCompatibilityTest",
            "AesCmacTestvectorsTest",
            "AesCtrTest",
            "AesCtrCompatibilityTest",
            "AesCfbTest",
            "AesCfbCompatibilityTest",
            "AesOfbTest",
            "AesOfbCompatibilityTest",
            "AesEcbCompatibilityTest",
            "AesGcmTest",
            "AesGcmCompatibilityTest",
            "AesCcmTest",
            "AesCcmCompatibilityTest",
            "ChaCha20Poly1305Test",
            "ChaCha20Poly1305CompatibilityTest",
            "HmacTest",
            "HmacCompatibilityTest",
            "HmacTestvectorsTest",
            "EcdsaTest",
            "EcdsaCompatibilityTest",
            "EcdhCompatibilityTest",
            "EdDsaTest",
            "EdDsaCompatibilityTest",
            "EdDsaTestvectorsTest",
            "XdhCompatibilityTest",
            "XdhTestvectorsTest",
            "DhTest",
            "DhCompatibilityTest",
            "DsaCompatibilityTest",
            "DsaTestvectorsTest",
            "RsaOaepTest",
            "RsaOaepCompatibilityTest",
            "RsaPkcs1Test",
            "RsaPkcs1CompatibilityTest",
            "RsaPkcs1EsCompatibilityTest",
            "RsaPssTest",
            "RsaPssCompatibilityTest",
            "RsaRawCompatibilityTest",
        )
    }
}
