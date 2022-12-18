package dev.whyoleg.cryptography.signature

public interface Signature : Signer, Verifier
public interface SyncSignature : Signature, SyncSigner, SyncVerifier
public interface AsyncSignature : Signature, AsyncSigner, AsyncVerifier
