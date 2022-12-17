package dev.whyoleg.cryptography.jdk

//TODO: revisit - if it's needed?
internal inline fun <T> threadLocal(crossinline block: () -> T): ThreadLocal<T> = object : ThreadLocal<T>() {
    override fun initialValue(): T = block()
}
