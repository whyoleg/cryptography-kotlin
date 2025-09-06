/*
 * Test tuning utilities (e.g., fast mode to reduce iterations locally)
 */
package dev.whyoleg.cryptography.providers.tests

object TestTuning {
    val fast: Boolean get() = FastFlag.fast
}

expect object FastFlag {
    val fast: Boolean
}

