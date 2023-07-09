/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk

private val maxPooled = Runtime.getRuntime().availableProcessors() + 2

internal sealed class Pooled<T>(protected val instantiate: () -> T) {
    class Empty<T>(instantiate: () -> T) : Pooled<T>(instantiate) {
        override fun get(): T = instantiate()
        override fun put(value: T) {}
    }

    class Cached<T>(instantiate: () -> T) : Pooled<T>(instantiate) {
        private val pooled = ArrayDeque<T>()

        override fun get(): T {
            synchronized(this) {
                pooled.firstOrNull()
            }?.let { return it }

            return instantiate()
        }

        override fun put(value: T) {
            synchronized(this) {
                if (pooled.size < maxPooled) {
                    pooled.addLast(value)
                }
            }
        }
    }

    protected abstract fun get(): T
    protected abstract fun put(value: T)

    inline fun <R> use(block: (T) -> R): R {
        val instance = get()
        try {
            return block(instance)
        } finally {
            put(instance)
        }
    }
}
