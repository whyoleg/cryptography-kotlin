package dev.whyoleg.cryptography.jdk

private val maxPooled = Runtime.getRuntime().availableProcessors() + 2

internal class Pooled<T>(private val instantiate: () -> T) {
    private val pooled = ArrayDeque<T>()

    private fun get(): T {
        synchronized(this) {
            pooled.firstOrNull()
        }?.let { return it }

        return instantiate()
    }

    private fun put(value: T) {
        synchronized(this) {
            if (pooled.size < maxPooled) {
                pooled.addLast(value)
            }
        }
    }

    inline fun <R> use(block: (T) -> R): R {
        val instance = get()
        try {
            return block(instance)
        } finally {
            put(instance)
        }
    }
}
