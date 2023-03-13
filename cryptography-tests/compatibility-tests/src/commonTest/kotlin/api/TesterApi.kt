package dev.whyoleg.cryptography.tests.compatibility.api

sealed class TesterApi {
    abstract val keys: TesterStorageApi
    abstract val keyPairs: TesterStorageApi
    abstract val digests: TesterStorageApi
    abstract val signatures: TesterStorageApi
    abstract val ciphers: TesterStorageApi
}
