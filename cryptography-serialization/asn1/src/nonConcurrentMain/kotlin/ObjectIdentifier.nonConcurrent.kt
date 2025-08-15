package dev.whyoleg.cryptography.serialization.asn1

// no concurrency here
internal actual val ObjectIdentifierCache: MutableMap<String, ObjectIdentifier> = mutableMapOf()
