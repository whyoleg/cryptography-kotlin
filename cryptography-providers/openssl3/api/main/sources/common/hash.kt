package dev.whyoleg.cryptography.openssl3

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.kcwrapper.libcrypto3.cinterop.*
import kotlinx.cinterop.*

internal fun hashAlgorithm(digest: CryptographyAlgorithmId<Digest>): String = when (digest) {
    SHA1   -> "SHA1"
    SHA256 -> "SHA256"
    SHA384 -> "SHA384"
    SHA512 -> "SHA512"
    else   -> throw CryptographyException("Unsupported hash algorithm: $digest")
}

//move out of hash file
internal fun NativePlacement.OSSL_PARAM_array(vararg values: CValue<OSSL_PARAM>): CArrayPointer<OSSL_PARAM> {
    val params = allocArray<OSSL_PARAM>(values.size + 1)
    values.forEachIndexed { index, value -> value.place(params[index].ptr) }
    OSSL_PARAM_construct_end().place(params[values.size].ptr)
    return params
}
