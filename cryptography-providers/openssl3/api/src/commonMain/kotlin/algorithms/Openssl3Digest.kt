/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import kotlin.experimental.*
import kotlin.native.ref.*

internal class Openssl3Digest(
    algorithm: String,
    override val id: CryptographyAlgorithmId<Digest>,
) : Hasher, Digest {
    override fun hasher(): Hasher = this

    private val md = EVP_MD_fetch(null, algorithm, null)

    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = createCleaner(md, ::EVP_MD_free)

    private val digestSize = EVP_MD_get_size(md)

    override fun hashBlocking(data: ByteArray): ByteArray {
        val context = checkError(EVP_MD_CTX_new())
        try {
            val digest = ByteArray(digestSize)
            checkError(EVP_DigestInit(context, md))
            @OptIn(UnsafeNumber::class)
            checkError(EVP_DigestUpdate(context, data.safeRefTo(0), data.size.convert()))
            checkError(EVP_DigestFinal(context, digest.refToU(0), null))
            return digest
        } finally {
            EVP_MD_CTX_free(context)
        }
    }
}
