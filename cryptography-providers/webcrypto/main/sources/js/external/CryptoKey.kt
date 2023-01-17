package dev.whyoleg.cryptography.webcrypto.external

internal external interface CryptoKey {
    val type: String // "secret", "private", "public"
    val extractable: Boolean
    val algorithm: Algorithm
    val usages: Array<String> // "encrypt" | "decrypt" | "sign" | "verify" | "deriveKey" | "deriveBits" | "wrapKey" | "unwrapKey"
}

internal external interface CryptoKeyPair {
    val privateKey: CryptoKey
    val publicKey: CryptoKey
}
