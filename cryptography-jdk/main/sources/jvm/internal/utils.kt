package dev.whyoleg.cryptography.jdk.internal

//TODO: replace with pooling
internal inline fun <T> threadLocal(crossinline block: () -> T): ThreadLocal<T> = object : ThreadLocal<T>() {
    override fun initialValue(): T = block()
}
