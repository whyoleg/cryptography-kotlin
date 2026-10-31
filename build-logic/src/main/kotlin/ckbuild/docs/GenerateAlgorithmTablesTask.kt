/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild.docs

import ckbuild.docs.ProviderSupport.*
import ckbuild.providertests.*
import org.gradle.api.*
import org.gradle.api.file.*
import org.gradle.api.tasks.*

abstract class GenerateAlgorithmTablesTask : DefaultTask() {

    // `limitations.json`, see `UpdateTestLimitationsTask`
    @get:InputFile
    abstract val limitationsFile: RegularFileProperty

    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty

    @TaskAction
    fun generate() {
        val outputDir = outputDirectory.get().asFile
        outputDir.deleteRecursively()
        outputDir.mkdirs()

        val limitations = readTestLimitations(limitationsFile.get().asFile)
        limitations.checkCoverage()
        val support = algorithms.values.flatten().associateWith { algorithm ->
            Provider.entries.associateWith { provider -> limitations.support(algorithm, provider) }
        }

        for (operation in Operation.entries) {
            outputDir.resolve(operation.snippetFile).writeText(
                buildTable(
                    table = listOf(operation to algorithms.getValue(operation)),
                    renderOperationHeaders = false,
                    support = { algorithm, provider -> support.getValue(algorithm).getValue(provider) },
                )
            )
        }

        outputDir.resolve("all-by-operation.md").writeText(
            buildTable(
                table = algorithms.toList().sortedBy { it.first/*operation*/ },
                renderOperationHeaders = true,
                support = { algorithm, provider -> support.getValue(algorithm).getValue(provider) },
            )
        )
    }
}

abstract class UpdateReadmeAlgorithmTableTask : DefaultTask() {

    @get:InputFile
    abstract val readmeFile: RegularFileProperty

    @TaskAction
    fun update() {
        val file = readmeFile.get().asFile
        val content = file.readText()
        val expected = buildReadmeContent(content)
        file.writeText(expected)
        if (content != expected) {
            throw GradleException(
                "README.md algorithm table was out of date and has been updated. Please commit the changes."
            )
        }
    }
}

// region Enums

private enum class Status(
    val icon: String,
    val description: String,
) {
    Modern("star", "Recommended"),
    Delicate("warning", "Requires careful use"),
    Legacy("biohazard", "Legacy or unsafe"),
}

private enum class Operation(
    val displayName: String,
    val page: String,
    val snippetFile: String,
) {
    Hashing("Hashing", "primitives/operations/hashing.md", "hashing.md"),
    MAC("MAC", "primitives/operations/mac.md", "mac.md"),
    Signing("Digital Signatures", "primitives/operations/digital-signatures.md", "signing.md"),
    AEAD("AEAD", "primitives/operations/aead.md", "aead.md"),
    SymmetricEncryption("Symmetric Encryption", "primitives/operations/symmetric-encryption.md", "symmetric-encryption.md"),
    PublicKeyEncryption("Public-Key Encryption", "primitives/operations/public-key-encryption.md", "public-key-encryption.md"),
    KeyAgreement("Key Agreement", "primitives/operations/key-agreement.md", "key-agreement.md"),
    KeyDerivation("Key Derivation", "primitives/operations/key-derivation.md", "key-derivation.md"),
}

// testProviders: providers of environments in `limitations.json`
private enum class Provider(val displayName: String, vararg val testProviders: String) {
    JDK("JDK", "jdk.default", "jdk.bc"),
    WebCrypto("WebCrypto", "webcrypto"),
    Apple("Apple", "apple"),

    //    CryptoKit("CryptoKit", "cryptokit"), TODO: enable it back later on
    OpenSSL3("OpenSSL3", "openssl3-3.0", "openssl3-3.x"),
}

private sealed class ProviderSupport {
    data object Supported : ProviderSupport()

    // `unsupported`: reasons why the algorithm is not supported in some environments, f.e. on older JDK
    // `limitations`: limited operations, f.e. some curves or key formats
    data class Limited(val unsupported: List<String>, val limitations: List<String>) : ProviderSupport()

    data object Unsupported : ProviderSupport()
}

// endregion

// region Algorithm Data

private data class Algorithm(
    val id: String,
    val operation: Operation,
    val status: Status? = null,
    val apiPath: String,
    // test suite in `limitations.json`, from which the support of providers is derived
    val suite: String = id,
) {
    init {
        require(apiPath.isNotBlank()) { "Algorithm '$id' has an empty API path" }
    }
}

private val algorithms = listOf(
    // AES
    Algorithm(
        id = "AES-GCM",
        operation = Operation.AEAD,
        status = Status.Modern,
        apiPath = "-a-e-s/-g-c-m",
    ),
    Algorithm(
        id = "AES-CCM",
        operation = Operation.AEAD,
        apiPath = "-a-e-s/-c-c-m",
    ),
    Algorithm(
        id = "AES-CBC",
        operation = Operation.SymmetricEncryption,
        apiPath = "-a-e-s/-c-b-c",
    ),
    Algorithm(
        id = "AES-CTR",
        operation = Operation.SymmetricEncryption,
        apiPath = "-a-e-s/-c-t-r",
    ),
    Algorithm(
        id = "AES-CMAC",
        operation = Operation.MAC,
        apiPath = "-a-e-s/-c-m-a-c",
    ),
    Algorithm(
        id = "AES-ECB",
        operation = Operation.SymmetricEncryption,
        status = Status.Legacy,
        apiPath = "-a-e-s/-e-c-b",
    ),
    Algorithm(
        id = "AES-OFB",
        operation = Operation.SymmetricEncryption,
        status = Status.Delicate,
        apiPath = "-a-e-s/-o-f-b",
    ),
    Algorithm(
        id = "AES-CFB",
        operation = Operation.SymmetricEncryption,
        status = Status.Delicate,
        apiPath = "-a-e-s/-c-f-b",
    ),
    Algorithm(
        id = "AES-CFB8",
        operation = Operation.SymmetricEncryption,
        status = Status.Delicate,
        apiPath = "-a-e-s/-c-f-b8",
    ),

    // ChaCha20
    Algorithm(
        id = "ChaCha20-Poly1305",
        operation = Operation.AEAD,
        status = Status.Modern,
        apiPath = "-cha-cha20-poly1305",
    ),

    // RSA
    Algorithm(
        id = "RSA-OAEP",
        operation = Operation.PublicKeyEncryption,
        apiPath = "-r-s-a/-o-a-e-p",
    ),
    Algorithm(
        id = "RSA-PKCS1",
        suite = "RSA-PKCS1-V1.5-encryption",
        operation = Operation.PublicKeyEncryption,
        status = Status.Legacy,
        apiPath = "-r-s-a/-p-k-c-s1",
    ),
    Algorithm(
        id = "RSA-RAW",
        operation = Operation.PublicKeyEncryption,
        status = Status.Legacy,
        apiPath = "-r-s-a/-r-a-w",
    ),
    Algorithm(
        id = "RSA-PSS",
        operation = Operation.Signing,
        apiPath = "-r-s-a/-p-s-s",
    ),
    Algorithm(
        id = "RSA-PKCS1",
        suite = "RSA-PKCS1-V1.5-signature",
        operation = Operation.Signing,
        apiPath = "-r-s-a/-p-k-c-s1",
    ),

    // EC
    Algorithm(
        id = "ECDSA",
        operation = Operation.Signing,
        status = Status.Modern,
        apiPath = "-e-c-d-s-a",
    ),
    Algorithm(
        id = "ECDH",
        operation = Operation.KeyAgreement,
        status = Status.Modern,
        apiPath = "-e-c-d-h",
    ),

    // EdDSA & XDH
    Algorithm(
        id = "EdDSA",
        operation = Operation.Signing,
        status = Status.Modern,
        apiPath = "-ed-d-s-a",
    ),
    Algorithm(
        id = "XDH",
        operation = Operation.KeyAgreement,
        status = Status.Modern,
        apiPath = "-x-d-h",
    ),

    // DH & DSA
    Algorithm(
        id = "DH",
        operation = Operation.KeyAgreement,
        apiPath = "-d-h",
    ),
    Algorithm(
        id = "DSA",
        operation = Operation.Signing,
        apiPath = "-d-s-a",
    ),

    // SHA
    Algorithm(
        id = "SHA-224",
        operation = Operation.Hashing,
        apiPath = "-s-h-a224",
    ),
    Algorithm(
        id = "SHA-256",
        operation = Operation.Hashing,
        apiPath = "-s-h-a256",
    ),
    Algorithm(
        id = "SHA-384",
        operation = Operation.Hashing,
        apiPath = "-s-h-a384",
    ),
    Algorithm(
        id = "SHA-512",
        operation = Operation.Hashing,
        apiPath = "-s-h-a512",
    ),
    Algorithm(
        id = "SHA3-224",
        operation = Operation.Hashing,
        apiPath = "-s-h-a3_224",
    ),
    Algorithm(
        id = "SHA3-256",
        operation = Operation.Hashing,
        apiPath = "-s-h-a3_256",
    ),
    Algorithm(
        id = "SHA3-384",
        operation = Operation.Hashing,
        apiPath = "-s-h-a3_384",
    ),
    Algorithm(
        id = "SHA3-512",
        operation = Operation.Hashing,
        apiPath = "-s-h-a3_512",
    ),
    Algorithm(
        id = "SHA-1",
        operation = Operation.Hashing,
        status = Status.Legacy,
        apiPath = "-s-h-a1",
    ),

    // Legacy digests
    Algorithm(
        id = "MD5",
        operation = Operation.Hashing,
        status = Status.Legacy,
        apiPath = "-m-d5",
    ),
    Algorithm(
        id = "RIPEMD-160",
        operation = Operation.Hashing,
        status = Status.Delicate,
        apiPath = "-r-i-p-e-m-d160",
    ),

    // MAC
    Algorithm(
        id = "HMAC",
        operation = Operation.MAC,
        apiPath = "-h-m-a-c",
    ),

    // KDF
    Algorithm(
        id = "PBKDF2",
        operation = Operation.KeyDerivation,
        apiPath = "-p-b-k-d-f2",
    ),
    Algorithm(
        id = "HKDF",
        operation = Operation.KeyDerivation,
        apiPath = "-h-k-d-f",
    ),
).groupBy(Algorithm::operation)

// endregion

// region Support

// every tested suite is documented and every documented algorithm is tested by every provider
private fun TestLimitations.checkCoverage() {
    val unknownProviders =
        environments.keys.map { it.substringBefore('/') }.toSet() - Provider.entries.flatMap { it.testProviders.toList() }.toSet()
    if (unknownProviders.isNotEmpty()) throw GradleException("Providers are not mapped to docs: $unknownProviders")

    val suites = environments.values.flatMapTo(mutableSetOf()) { it.keys }
    val documentedSuites = algorithms.values.flatten().mapTo(mutableSetOf(), Algorithm::suite)
    if (suites != documentedSuites) throw GradleException(
        "Documented algorithms don't match tested suites: undocumented=${suites - documentedSuites}, untested=${documentedSuites - suites}"
    )
}

private fun TestLimitations.environments(provider: Provider): List<String> = provider.testProviders.flatMap(::environments)

// - Unsupported: the suite is unsupported in all environments of the provider
// - Limited: reasons why the suite is unsupported in some environments,
//   and descriptions of failing (or lenient) operations, except for those failing because of other unsupported suites (f.e. digests),
//   which are shown in their rows
// - Supported: otherwise
private fun TestLimitations.support(algorithm: Algorithm, provider: Provider): ProviderSupport {
    val results = environments(provider).mapNotNull { environment ->
        environments.getValue(environment)[algorithm.suite]?.let { environment to it }
    }
    if (results.isEmpty()) throw GradleException("'${algorithm.suite}' is not tested for $provider")
    if (results.all { (_, limitations) -> limitations.unsupported.isNotEmpty() }) return Unsupported

    val unsupported = results.flatMap { (_, limitations) -> limitations.unsupported }.distinct().sorted()
    val limitations = results.flatMap { (environment, limitations) ->
        val dependencies = environments.getValue(environment).values.flatMapTo(mutableSetOf()) { it.unsupported }
        limitations.limitations.filter { it.kind != "Skipped" && it.description !in dependencies }.map { it.description }
    }.distinct().sorted()
    return when {
        unsupported.isEmpty() && limitations.isEmpty() -> Supported
        else                                           -> Limited(unsupported, limitations)
    }
}

// endregion

// region Table Rendering

private fun buildTable(
    table: List<Pair<Operation, List<Algorithm>>>,
    renderOperationHeaders: Boolean,
    support: (Algorithm, Provider) -> ProviderSupport,
): String = buildString {
    require(table.isNotEmpty()) { "Table must have at least one row" }

    fun appendRow(main: String, providerValue: (Provider) -> String) {
        appendLine("| $main | ${Provider.entries.joinToString(" | ", transform = providerValue)} |")
    }

    val footnotes = mutableListOf<Pair<String, String>>()

    appendRow("Algorithm") { it.displayName }
    appendRow("---") { "---" }

    for ((operation, algorithms) in table) {
        if (renderOperationHeaders) appendRow(linkToOperation(operation)) { "" }
        algorithms.forEach { algorithm ->
            appendRow(linkToAlgorithm(algorithm)) { provider ->
                when (val support = support(algorithm, provider)) {
                    is Supported   -> ":white_check_mark:"
                    is Limited -> {
                        val id = "${algorithm.suite}-${provider.name}".lowercase()
                        footnotes += id to footnote(algorithm, provider, support)
                        ":white_check_mark: [^$id]"
                    }
                    is Unsupported -> ":x:"
                }
            }
        }
    }
    appendFootnotes(footnotes)
}

// one footnote per cell, shown as a tooltip on hover; reasons why the algorithm is not supported in some environments are bold
private fun footnote(algorithm: Algorithm, provider: Provider, support: Limited): String = buildString {
    appendLine("${algorithm.id} limitations in ${provider.displayName}:")
    appendLine()
    support.unsupported.forEach { appendLine("    - **$it**") }
    support.limitations.forEach { appendLine("    - $it") }
}

private fun StringBuilder.appendFootnotes(footnotes: List<Pair<String, String>>) {
    if (footnotes.isEmpty()) return
    appendLine()
    for ((id, content) in footnotes) {
        appendLine("[^$id]: $content")
    }
}

private fun linkToAlgorithm(alg: Algorithm): String {
    val status = when (alg.status) {
        null -> ""
        else -> " :${alg.status.icon}:{ title=\"${alg.status.description}\" }"
    }
    val rel = relativePath("api/cryptography-core/dev.whyoleg.cryptography.algorithms/${alg.apiPath}/index.html")
    return "[${alg.id}]($rel)$status"
}

private fun linkToOperation(op: Operation): String {
    return "**[${op.displayName}](${relativePath(op.page)})**"
}

private fun relativePath(toPage: String): String {
    val fromParts = "primitives/operations".split("/").filter { it.isNotEmpty() }
    val toParts = toPage.split("/").filter { it.isNotEmpty() }
    val common = fromParts.zip(toParts).takeWhile { (a, b) -> a == b }.size
    return (List(fromParts.size - common) { ".." } + toParts.drop(common)).joinToString("/")
}

// endregion

// region README

private const val README_MARKER_START = "<!-- SUPPORTED_ALGORITHMS_START -->"
private const val README_MARKER_END = "<!-- SUPPORTED_ALGORITHMS_END -->"

private fun buildReadmeContent(currentContent: String): String {
    val startIdx = currentContent.indexOf(README_MARKER_START)
    val endIdx = currentContent.indexOf(README_MARKER_END)
    require(startIdx in 0..<endIdx) {
        "README.md must contain $README_MARKER_START and $README_MARKER_END markers"
    }

    val before = currentContent.substring(0, startIdx + README_MARKER_START.length)
    val after = currentContent.substring(endIdx)
    return before + "\n\n" + buildReadmeTable() + "\n" + after
}

private fun buildReadmeTable(): String = buildString {
    appendLine("| Operation | Algorithms |")
    appendLine("|-----------|------------|")

    for (operation in Operation.entries) {
        val algorithmNames = algorithms.getValue(operation).joinToString(", ", transform = Algorithm::id)
        val opLink = "[${operation.displayName}](https://whyoleg.github.io/cryptography-kotlin/${operation.page.removeSuffix(".md")}/)"
        appendLine("| $opLink | $algorithmNames |")
    }
}

// endregion
