package dev.whyoleg.cryptography.signature

public interface Mac : Signer, Verifier
public interface SyncMac : Mac, SyncSigner, SyncVerifier
public interface AsyncMac : Mac, AsyncSigner, AsyncVerifier
