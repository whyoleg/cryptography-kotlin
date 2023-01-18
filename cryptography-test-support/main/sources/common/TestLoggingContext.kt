package dev.whyoleg.cryptography.test.support

class TestLoggingContext(private val providerName: String) {
    fun log(message: String) {
        println("[TEST|$providerName] $message")
    }
}
