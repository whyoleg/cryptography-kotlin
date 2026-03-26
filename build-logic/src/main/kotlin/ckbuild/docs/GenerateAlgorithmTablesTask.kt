/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild.docs

import ckbuild.docs.ProviderSupport.*
import org.gradle.api.*
import org.gradle.api.file.*
import org.gradle.api.tasks.*

abstract class GenerateAlgorithmTablesTask : DefaultTask() {

    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty

    @TaskAction
    fun generate() {
        val outputDir = outputDirectory.get().asFile
        outputDir.deleteRecursively()
        outputDir.mkdirs()

        for (operation in Operation.entries) {
            outputDir.resolve(operation.snippetFile).writeText(
                buildTable(
                    table = listOf(operation to algorithms.getValue(operation)),
                    renderOperationHeaders = false
                )
            )
        }

        outputDir.resolve("all-by-operation.md").writeText(
            buildTable(
                table = algorithms.toList().sortedBy { it.first/*operation*/ },
                renderOperationHeaders = true
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

private enum class Provider(val displayName: String) {
    JDK("JDK"),
    WebCrypto("WebCrypto"),
    Apple("Apple"),
    CryptoKit("CryptoKit"),
    OpenSSL3("OpenSSL3"),
}

private sealed class ProviderSupport {
    data object Supported : ProviderSupport()
    data class Limited(val notes: List<String>) : ProviderSupport() {
        constructor(vararg notes: String) : this(notes.toList())

        init {
            require(notes.isNotEmpty()) { "Limited notes cannot be empty" }
        }
    }

    data object Unsupported : ProviderSupport()
}

// endregion

// region Algorithm Data

private data class Algorithm(
    val id: String,
    val operation: Operation,
    val status: Status? = null,
    val apiPath: String,
    val providers: Map<Provider, ProviderSupport>,
) {
    init {
        val missing = Provider.entries.toSet() - providers.keys
        require(missing.isEmpty()) { "Algorithm '$id' is missing provider entries: $missing" }
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
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Limited("192-bit keys may not be supported in some browsers"),
            Provider.Apple to Unsupported,
            Provider.CryptoKit to Limited("128-bit (default) tag only"),
            Provider.OpenSSL3 to Supported,
        ),
    ),
    Algorithm(
        id = "AES-CCM",
        operation = Operation.AEAD,
        apiPath = "-a-e-s/-c-c-m",
        providers = mapOf(
            Provider.JDK to Limited("Requires BouncyCastle"),
            Provider.WebCrypto to Unsupported,
            Provider.Apple to Unsupported,
            Provider.CryptoKit to Unsupported,
            Provider.OpenSSL3 to Supported,
        ),
    ),
    Algorithm(
        id = "AES-CBC",
        operation = Operation.SymmetricEncryption,
        apiPath = "-a-e-s/-c-b-c",
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Limited("Only padding=true supported", "192-bit keys may not be supported in some browsers"),
            Provider.Apple to Supported,
            Provider.CryptoKit to Unsupported,
            Provider.OpenSSL3 to Supported,
        ),
    ),
    Algorithm(
        id = "AES-CTR",
        operation = Operation.SymmetricEncryption,
        apiPath = "-a-e-s/-c-t-r",
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Limited("192-bit keys may not be supported in some browsers"),
            Provider.Apple to Supported,
            Provider.CryptoKit to Unsupported,
            Provider.OpenSSL3 to Supported,
        ),
    ),
    Algorithm(
        id = "AES-CMAC",
        operation = Operation.MAC,
        apiPath = "-a-e-s/-c-m-a-c",
        providers = mapOf(
            Provider.JDK to Limited("Requires BouncyCastle"),
            Provider.WebCrypto to Unsupported,
            Provider.Apple to Unsupported,
            Provider.CryptoKit to Unsupported,
            Provider.OpenSSL3 to Supported,
        ),
    ),
    Algorithm(
        id = "AES-ECB",
        operation = Operation.SymmetricEncryption,
        status = Status.Legacy,
        apiPath = "-a-e-s/-e-c-b",
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Unsupported,
            Provider.Apple to Supported,
            Provider.CryptoKit to Unsupported,
            Provider.OpenSSL3 to Supported,
        ),
    ),
    Algorithm(
        id = "AES-OFB",
        operation = Operation.SymmetricEncryption,
        status = Status.Delicate,
        apiPath = "-a-e-s/-o-f-b",
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Unsupported,
            Provider.Apple to Supported,
            Provider.CryptoKit to Unsupported,
            Provider.OpenSSL3 to Supported,
        ),
    ),
    Algorithm(
        id = "AES-CFB",
        operation = Operation.SymmetricEncryption,
        status = Status.Delicate,
        apiPath = "-a-e-s/-c-f-b",
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Unsupported,
            Provider.Apple to Supported,
            Provider.CryptoKit to Unsupported,
            Provider.OpenSSL3 to Supported,
        ),
    ),
    Algorithm(
        id = "AES-CFB8",
        operation = Operation.SymmetricEncryption,
        status = Status.Delicate,
        apiPath = "-a-e-s/-c-f-b8",
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Unsupported,
            Provider.Apple to Supported,
            Provider.CryptoKit to Unsupported,
            Provider.OpenSSL3 to Supported,
        ),
    ),

    // ChaCha20
    Algorithm(
        id = "ChaCha20-Poly1305",
        operation = Operation.AEAD,
        status = Status.Modern,
        apiPath = "-cha-cha20-poly1305",
        providers = mapOf(
            Provider.JDK to Limited("Requires JDK 11+; use BouncyCastle on older JDK or Android"),
            Provider.WebCrypto to Unsupported,
            Provider.Apple to Unsupported,
            Provider.CryptoKit to Supported,
            Provider.OpenSSL3 to Supported,
        ),
    ),

    // RSA
    Algorithm(
        id = "RSA-OAEP",
        operation = Operation.PublicKeyEncryption,
        apiPath = "-r-s-a/-o-a-e-p",
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Supported,
            Provider.Apple to Supported,
            Provider.CryptoKit to Unsupported,
            Provider.OpenSSL3 to Supported,
        ),
    ),
    Algorithm(
        id = "RSA-PKCS1",
        operation = Operation.PublicKeyEncryption,
        status = Status.Legacy,
        apiPath = "-r-s-a/-p-k-c-s1",
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Unsupported,
            Provider.Apple to Supported,
            Provider.CryptoKit to Unsupported,
            Provider.OpenSSL3 to Supported,
        ),
    ),
    Algorithm(
        id = "RSA-RAW",
        operation = Operation.PublicKeyEncryption,
        status = Status.Legacy,
        apiPath = "-r-s-a/-r-a-w",
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Unsupported,
            Provider.Apple to Supported,
            Provider.CryptoKit to Unsupported,
            Provider.OpenSSL3 to Supported,
        ),
    ),
    Algorithm(
        id = "RSA-PSS",
        operation = Operation.Signing,
        apiPath = "-r-s-a/-p-s-s",
        providers = mapOf(
            Provider.JDK to Limited("Not available on Android; use BouncyCastle"),
            Provider.WebCrypto to Supported,
            Provider.Apple to Supported,
            Provider.CryptoKit to Unsupported,
            Provider.OpenSSL3 to Supported,
        ),
    ),
    Algorithm(
        id = "RSA-PKCS1",
        operation = Operation.Signing,
        apiPath = "-r-s-a/-p-k-c-s1",
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Supported,
            Provider.Apple to Supported,
            Provider.CryptoKit to Unsupported,
            Provider.OpenSSL3 to Supported,
        ),
    ),

    // EC
    Algorithm(
        id = "ECDSA",
        operation = Operation.Signing,
        status = Status.Modern,
        apiPath = "-e-c-d-s-a",
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Limited("Doesn't support working with pre-hashed data"),
            Provider.Apple to Supported,
            Provider.CryptoKit to Limited("Doesn't support working with pre-hashed data"),
            Provider.OpenSSL3 to Supported,
        ),
    ),
    Algorithm(
        id = "ECDH",
        operation = Operation.KeyAgreement,
        status = Status.Modern,
        apiPath = "-e-c-d-h",
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Supported,
            Provider.Apple to Unsupported,
            Provider.CryptoKit to Supported,
            Provider.OpenSSL3 to Supported,
        ),
    ),

    // EdDSA & XDH
    Algorithm(
        id = "EdDSA",
        operation = Operation.Signing,
        status = Status.Modern,
        apiPath = "-ed-d-s-a",
        providers = mapOf(
            Provider.JDK to Limited("Requires JDK 15+; use BouncyCastle on older JDK or Android"),
            Provider.WebCrypto to Limited("Ed25519 only; browser support varies"),
            Provider.Apple to Unsupported,
            Provider.CryptoKit to Limited("Ed25519 only"),
            Provider.OpenSSL3 to Supported,
        ),
    ),
    Algorithm(
        id = "XDH",
        operation = Operation.KeyAgreement,
        status = Status.Modern,
        apiPath = "-x-d-h",
        providers = mapOf(
            Provider.JDK to Limited("Requires JDK 11+; use BouncyCastle on older JDK or Android"),
            Provider.WebCrypto to Limited("X25519 only; browser support varies"),
            Provider.Apple to Unsupported,
            Provider.CryptoKit to Limited("X25519 only"),
            Provider.OpenSSL3 to Supported,
        ),
    ),

    // DH & DSA
    Algorithm(
        id = "DH",
        operation = Operation.KeyAgreement,
        apiPath = "-d-h",
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Unsupported,
            Provider.Apple to Unsupported,
            Provider.CryptoKit to Unsupported,
            Provider.OpenSSL3 to Supported,
        ),
    ),
    Algorithm(
        id = "DSA",
        operation = Operation.Signing,
        apiPath = "-d-s-a",
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Unsupported,
            Provider.Apple to Unsupported,
            Provider.CryptoKit to Unsupported,
            Provider.OpenSSL3 to Supported,
        ),
    ),

    // SHA
    Algorithm(
        id = "SHA224",
        operation = Operation.Hashing,
        apiPath = "-s-h-a224",
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Unsupported,
            Provider.Apple to Supported,
            Provider.CryptoKit to Unsupported,
            Provider.OpenSSL3 to Supported,
        ),
    ),
    Algorithm(
        id = "SHA256",
        operation = Operation.Hashing,
        apiPath = "-s-h-a256",
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Supported,
            Provider.Apple to Supported,
            Provider.CryptoKit to Supported,
            Provider.OpenSSL3 to Supported,
        ),
    ),
    Algorithm(
        id = "SHA384",
        operation = Operation.Hashing,
        apiPath = "-s-h-a384",
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Supported,
            Provider.Apple to Supported,
            Provider.CryptoKit to Supported,
            Provider.OpenSSL3 to Supported,
        ),
    ),
    Algorithm(
        id = "SHA512",
        operation = Operation.Hashing,
        apiPath = "-s-h-a512",
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Supported,
            Provider.Apple to Supported,
            Provider.CryptoKit to Supported,
            Provider.OpenSSL3 to Supported,
        ),
    ),
    Algorithm(
        id = "SHA3",
        operation = Operation.Hashing,
        apiPath = "-s-h-a3_256",
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Unsupported,
            Provider.Apple to Unsupported,
            Provider.CryptoKit to Unsupported,
            Provider.OpenSSL3 to Supported,
        ),
    ),
    Algorithm(
        id = "SHA1",
        operation = Operation.Hashing,
        status = Status.Legacy,
        apiPath = "-s-h-a1",
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Supported,
            Provider.Apple to Supported,
            Provider.CryptoKit to Supported,
            Provider.OpenSSL3 to Supported,
        ),
    ),

    // Legacy digests
    Algorithm(
        id = "MD5",
        operation = Operation.Hashing,
        status = Status.Legacy,
        apiPath = "-m-d5",
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Unsupported,
            Provider.Apple to Supported,
            Provider.CryptoKit to Supported,
            Provider.OpenSSL3 to Supported,
        ),
    ),
    Algorithm(
        id = "RIPEMD160",
        operation = Operation.Hashing,
        status = Status.Delicate,
        apiPath = "-r-i-p-e-m-d160",
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Unsupported,
            Provider.Apple to Unsupported,
            Provider.CryptoKit to Unsupported,
            Provider.OpenSSL3 to Supported,
        ),
    ),

    // MAC
    Algorithm(
        id = "HMAC",
        operation = Operation.MAC,
        apiPath = "-h-m-a-c",
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Supported,
            Provider.Apple to Supported,
            Provider.CryptoKit to Supported,
            Provider.OpenSSL3 to Supported,
        ),
    ),

    // KDF
    Algorithm(
        id = "PBKDF2",
        operation = Operation.KeyDerivation,
        apiPath = "-p-b-k-d-f2",
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Supported,
            Provider.Apple to Supported,
            Provider.CryptoKit to Unsupported,
            Provider.OpenSSL3 to Supported,
        ),
    ),
    Algorithm(
        id = "HKDF",
        operation = Operation.KeyDerivation,
        apiPath = "-h-k-d-f",
        providers = mapOf(
            Provider.JDK to Supported,
            Provider.WebCrypto to Supported,
            Provider.Apple to Supported,
            Provider.CryptoKit to Supported,
            Provider.OpenSSL3 to Supported,
        ),
    ),
).groupBy(Algorithm::operation)

// endregion

// region Table Rendering

private fun buildTable(
    table: List<Pair<Operation, List<Algorithm>>>,
    renderOperationHeaders: Boolean,
): String = buildString {
    require(table.isNotEmpty()) { "Table must have at least one row" }

    fun appendRow(main: String, providerValue: (Provider) -> String) {
        appendLine("| $main | ${Provider.entries.joinToString(" | ", transform = providerValue)} |")
    }

    val footnotes = collectFootnotes(table)

    appendRow("Algorithm") { it.displayName }
    appendRow("---") { "---" }

    for ((operation, algorithms) in table) {
        if (renderOperationHeaders) appendRow(linkToOperation(operation)) { "" }
        algorithms.forEach { algorithm ->
            appendRow(linkToAlgorithm(algorithm)) { provider ->
                when (val support = algorithm.providers.getValue(provider)) {
                    is Supported   -> ":white_check_mark:"
                    is Limited     -> ":white_check_mark: ${
                        support.notes.map(footnotes::getValue).sorted().joinToString(separator = " ") { "[^$it]" }
                    }"
                    is Unsupported -> ":x:"
                }
            }
        }
    }
    appendFootnotes(footnotes)
}

private fun collectFootnotes(table: List<Pair<Operation, List<Algorithm>>>): Map<String, Int> = buildMap {
    for ((_, algorithms) in table) {
        for (algorithm in algorithms) {
            for ((_, support) in algorithm.providers) {
                if (support is Limited) {
                    for (note in support.notes) {
                        getOrPut(note) { size + 1 }
                    }
                }
            }
        }
    }
}

private fun StringBuilder.appendFootnotes(footnotes: Map<String, Int>) {
    if (footnotes.isEmpty()) return
    appendLine()
    for ((note, idx) in footnotes) {
        appendLine("[^$idx]: $note")
        appendLine()
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
