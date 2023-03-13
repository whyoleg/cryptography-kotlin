package dev.whyoleg.cryptography.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.openssl3.*
import dev.whyoleg.cryptography.openssl3.internal.*
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

    override fun hashBlocking(dataInput: ByteArray): ByteArray {
        val context = checkError(EVP_MD_CTX_new())
        try {
            val digest = ByteArray(digestSize)
            checkError(EVP_DigestInit(context, md))
            checkError(EVP_DigestUpdate(context, dataInput.safeRefTo(0), dataInput.size.convert()))
            checkError(EVP_DigestFinal(context, digest.refToU(0), null))
            return digest
        } finally {
            EVP_MD_CTX_free(context)
        }
    }
}
