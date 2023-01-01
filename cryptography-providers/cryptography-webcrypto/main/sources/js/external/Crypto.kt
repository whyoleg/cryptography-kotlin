package dev.whyoleg.cryptography.webcrypto.external

internal external interface Crypto {
    val subtle: SubtleCrypto
    fun getRandomValues(array: ByteArray): ByteArray
}
