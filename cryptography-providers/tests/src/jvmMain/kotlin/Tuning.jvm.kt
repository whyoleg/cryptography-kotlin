package dev.whyoleg.cryptography.providers.tests

actual object FastFlag {
    actual val fast: Boolean
        get() = java.lang.Boolean.getBoolean("ck.fast")
}

