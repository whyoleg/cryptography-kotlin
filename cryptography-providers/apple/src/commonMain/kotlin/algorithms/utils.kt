/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.apple.algorithms

private val almostEmptyArray = ByteArray(1)

//this hack will be dropped with introducing of new IO or functions APIs
internal fun ByteArray.fixEmpty(): ByteArray = if (isNotEmpty()) this else almostEmptyArray
