package dev.whyoleg.cryptography.test.support

fun TestLoggingContext(
    enableLogs: Boolean = true,
    providerName: String,
): TestLoggingContext = when {
    enableLogs -> TestLoggingContext.Default(providerName)
    else       -> TestLoggingContext.Noop
}

//TODO: can not be sealed K/JS for some strange reason - create kotlin issue (fail in runtime)
abstract class TestLoggingContext {
    abstract fun log(message: String)

    class Default(private val providerName: String) : TestLoggingContext() {
        override fun log(message: String) {
            println("[TEST|$providerName] $message")
        }
    }

    object Noop : TestLoggingContext() {
        override fun log(message: String) {}
    }
}
