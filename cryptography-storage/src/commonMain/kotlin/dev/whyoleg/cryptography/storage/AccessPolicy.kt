package dev.whyoleg.cryptography.storage

/**
 * Provider-agnostic access policy that controls key generation/import and usage.
 * Implementations map these fields to platform-specific controls (e.g., Keychain attributes).
 */
@ExperimentalKeyStorageApi
public data class AccessPolicy(
    /** Require an interactive user presence/authentication on sensitive operations if supported. */
    val requireUserPresence: Boolean = false,
    /** Storage accessibility class (e.g., Keychain accessibility). */
    val accessibility: Accessibility = Accessibility.AfterFirstUnlock,
    /** Whether to bind keys to the current device or prefer hardware-bound storage when available. */
    val deviceBinding: DeviceBinding = DeviceBinding.None,
    /** Allow exporting private material (discouraged; defaults to false). */
    val exportablePrivate: Boolean = false,
)

/** Storage accessibility levels mapped by providers to platform capabilities. */
@ExperimentalKeyStorageApi
public enum class Accessibility {
    WhenUnlocked,
    AfterFirstUnlock,
    Always,
    WhenPasscodeSetThisDeviceOnly,
}

/** Device binding preference for generated/imported keys. */
@ExperimentalKeyStorageApi
public enum class DeviceBinding {
    /** No device binding requested. */
    None,
    /** Keep on this device only (non-migratable). */
    ThisDeviceOnly,
    /** Prefer hardware-backed secure enclave if available. */
    SecureEnclavePreferred,
}
