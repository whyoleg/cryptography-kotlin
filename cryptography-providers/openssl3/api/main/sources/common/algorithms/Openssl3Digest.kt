package dev.whyoleg.cryptography.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.openssl3.*
import dev.whyoleg.cryptography.operations.hash.*
import dev.whyoleg.kcwrapper.libcrypto3.cinterop.*
import kotlinx.cinterop.*
import kotlin.native.internal.*

internal class Openssl3Digest(
    algorithm: String,
    override val id: CryptographyAlgorithmId<Digest>,
) : Hasher, Digest {
    override fun hasher(): Hasher = this

    private val md = EVP_MD_fetch(null, algorithm, null)

    @OptIn(ExperimentalStdlibApi::class)
    private val cleaner = createCleaner(md, ::EVP_MD_free)

    private val digestSize = EVP_MD_get_size(md)

    @OptIn(ExperimentalUnsignedTypes::class)
    override fun hashBlocking(dataInput: ByteArray): ByteArray {
        val context = EVP_MD_CTX_new()
        try {
            val digest = ByteArray(digestSize)

            //TODO: error handling
            check(EVP_DigestInit(context, md) == 1)
            check(EVP_DigestUpdate(context, dataInput.fixEmpty().refTo(0), dataInput.size.convert()) == 1)
            check(EVP_DigestFinal(context, digest.asUByteArray().refTo(0), null) == 1)

            return digest
        } finally {
            EVP_MD_CTX_free(context)
        }
    }
}
