package dev.whyoleg.cryptography.test.utils

fun interface TestLogger {
    fun log(message: String)

    companion object {
        val Noop: TestLogger = TestLogger { }
    }
}

fun TestLogger(
    tag: String? = null,
    disabled: Boolean = false,
): TestLogger {
    if (disabled) return TestLogger.Noop

    val prefix = when (tag) {
        null -> "[TEST]"
        else -> "[TEST|$tag]"
    }
    return TestLogger { message -> println("$prefix $message") }
}
