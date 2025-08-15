package dev.whyoleg.cryptography.serialization.asn1

import java.util.concurrent.*

internal actual val ObjectIdentifierCache: MutableMap<String, ObjectIdentifier> = ConcurrentHashMap<String, ObjectIdentifier>()
