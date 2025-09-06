package dev.whyoleg.cryptography.providers.tests

actual object FastFlag {
    actual val fast: Boolean
        get() = try {
            val w: dynamic = js("typeof window !== 'undefined' ? window : null")
            (w != null) && (w.__CK_FAST__ == true)
        } catch (e: dynamic) {
            false
        }
}

