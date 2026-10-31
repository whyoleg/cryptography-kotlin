/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base

import dev.whyoleg.cryptography.*
import kotlin.concurrent.*
import kotlin.experimental.*
import kotlin.native.ref.*

// Owns a native handle and releases it exactly once: either explicitly via `close` or when the resource is collected.
// Anything that may outlive the current call should hold the `NativeResource` (which keeps the handle alive), not the raw handle.
// Only the creator of the resource should call `close`; objects sharing it (f.e. operations created from a key) should not.
@CryptographyProviderApi
@OptIn(ExperimentalNativeApi::class)
public class NativeResource<T : Any>(value: T, release: (T) -> Unit) : AutoCloseable {
    private val holder = Holder(value, release)
    private val cleaner = createCleaner(holder, Holder<T>::release)

    public fun access(): T = holder.access()
    override fun close(): Unit = holder.release()

    // the cleaner must not capture the `NativeResource` itself, so the state lives in a separate object
    private class Holder<T : Any>(private val value: T, private val release: (T) -> Unit) {
        private val released = AtomicInt(0)

        fun access(): T {
            check(released.value == 0) { "Already closed" }
            return value
        }

        fun release() {
            if (released.compareAndSet(0, 1)) release(value)
        }
    }
}
