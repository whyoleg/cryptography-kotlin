package dev.whyoleg.cryptography.storage

/**
 * Provider-agnostic key attributes returned alongside key handles.
 *
 * - [extractable]: whether the private material can be exported in any form.
 * - [persistent]: whether the key is stored by the platform and survives process restarts.
 * - [label]: optional provider label/alias used to look up the key (binary-safe).
 */
@ExperimentalKeyStorageApi
public data class KeyAttributes(
    val extractable: Boolean,
    val persistent: Boolean,
    val label: ByteArray?,
)
