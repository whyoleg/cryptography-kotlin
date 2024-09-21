/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.internal

import kotlin.concurrent.*
import kotlin.experimental.*
import kotlin.native.ref.*

// TODO: clozy use-cases

@OptIn(ExperimentalNativeApi::class)
internal abstract class SafeCloseable(closeAction: SafeCloseAction) : AutoCloseable {
    private val handler = CloseHandler(closeAction)
    private val cleaner = createCleaner(handler, CloseHandler::onClose)
    final override fun close(): Unit = handler.onClose()
}

internal interface SafeCloseAction {
    fun onClose()
}

internal inline fun <T> SafeCloseAction(resource: T, crossinline closeAction: (T) -> Unit): SafeCloseAction =
    object : SafeCloseAction {
        override fun onClose(): Unit = closeAction(resource)
    }

private class CloseHandler(private val closeAction: SafeCloseAction) {
    private val executed = AtomicInt(0)
    fun onClose() {
        if (executed.compareAndSet(0, 1)) closeAction.onClose()
    }
}

internal class Resource<T>(
    private var value: T?,
    private val recycle: (T) -> Unit,
) : AutoCloseable {
    fun access(): T = checkNotNull(value) { "Already closed" }

    override fun close() {
        recycle(value ?: return)
        value = null
    }
}
