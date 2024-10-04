/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk

private val maxPooled = Runtime.getRuntime().availableProcessors() + 2

// TODO: clozy use-case
internal sealed class Pooled<T>(protected val instantiate: () -> T) {
    class Empty<T>(instantiate: () -> T) : Pooled<T>(instantiate) {
        override fun borrow(): T = instantiate()
        override fun recycle(value: T) {}
    }

    class Cached<T>(instantiate: () -> T) : Pooled<T>(instantiate) {
        private val pooled = ArrayDeque<T>()

        override fun borrow(): T {
            return synchronized(this) {
                pooled.removeLastOrNull()
            } ?: instantiate()
        }

        override fun recycle(value: T) {
            synchronized(this) {
                if (pooled.size < maxPooled) {
                    pooled.addLast(value)
                }
            }
        }
    }

    protected abstract fun borrow(): T
    protected abstract fun recycle(value: T)

    fun borrowResource(): Resource<T> = Resource(this)
    inline fun borrowResource(initialize: T.() -> Unit): Resource<T> = borrowResource().apply { access().initialize() }

    inline fun <R> use(block: (T) -> R): R {
        val instance = borrow()
        try {
            return block(instance)
        } finally {
            recycle(instance)
        }
    }

    class Resource<T>(private val pooled: Pooled<T>) : AutoCloseable {
        private var _value: T? = pooled.borrow()

        fun access(): T = checkNotNull(_value) { "Already closed" }

        override fun close() {
            pooled.recycle(_value ?: return)
            _value = null
        }
    }
}
