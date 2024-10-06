/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*

internal class Openssl3Digest(
    private val md: CPointer<EVP_MD>,
    override val id: CryptographyAlgorithmId<Digest>,
) : Hasher, Digest, SafeCloseable(SafeCloseAction(md, ::EVP_MD_free)) {
    private val digestSize = EVP_MD_get_size(md)

    constructor(
        algorithm: String,
        id: CryptographyAlgorithmId<Digest>,
    ) : this(checkError(EVP_MD_fetch(null, algorithm, null)), id)

    override fun hasher(): Hasher = this
    override fun createHashFunction(): HashFunction {
        val context = checkError(EVP_MD_CTX_new())
        // TODO: error handle
        checkError(EVP_DigestInit(context, md))
        return Openssl3HashFunction(Resource(context, ::EVP_MD_CTX_free))
    }

    // inner class to have a reference to class and so `md` cleaner - so that `md` can be freed at the right time
    private inner class Openssl3HashFunction(
        private val context: Resource<CPointer<EVP_MD_CTX>>,
    ) : HashFunction, SafeCloseable(SafeCloseAction(context, AutoCloseable::close)) {
        @OptIn(UnsafeNumber::class)
        override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
            checkBounds(source.size, startIndex, endIndex)

            val context = context.access()
            source.usePinned {
                checkError(EVP_DigestUpdate(context, it.safeAddressOf(startIndex), (endIndex - startIndex).convert()))
            }
        }

        override fun hashIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
            checkBounds(destination.size, destinationOffset, destinationOffset + digestSize)

            val context = context.access()
            destination.usePinned {
                checkError(EVP_DigestFinal(context, it.safeAddressOf(destinationOffset).reinterpret(), null))
            }
            close()
            return digestSize
        }

        override fun hashToByteArray(): ByteArray {
            val output = ByteArray(digestSize)
            hashIntoByteArray(output)
            return output
        }
    }
}
