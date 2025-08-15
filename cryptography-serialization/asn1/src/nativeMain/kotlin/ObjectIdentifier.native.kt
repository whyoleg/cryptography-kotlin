package dev.whyoleg.cryptography.serialization.asn1

import kotlin.native.concurrent.*

// TODO: synchronize access to cache
@ThreadLocal
internal actual val ObjectIdentifierCache: MutableMap<String, ObjectIdentifier> = mutableMapOf()
