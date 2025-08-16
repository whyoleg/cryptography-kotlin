/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.testtool.api

import kotlinx.serialization.*

/**
 * The top-level testcase container.
 *
 * Title: Limbo
 */
@Serializable
data class Limbo(
    /**
     * The limbo schema version; this must currently always be 1
     *
     * Title: Version
     */
    val version: Int = 1,

    /**
     * One or more testcases in this testsuite
     *
     * Title: Testcases
     */
    val testcases: List<Testcase>,
)

/**
 * Represents an individual Limbo testcase.
 *
 * Title: Testcase
 */
@Serializable
data class Testcase(
    /**
     * A short, unique identifier for this testcase
     *
     * Title: Id
     * Pattern: ^([A-Za-z][A-Za-z0-9-.]+::)*([A-Za-z][A-Za-z0-9-.]+)$
     */
    val id: String,

    /**
     * A list of testcase IDs that this testcase is mutually incompatible with
     *
     * Title: Conflicts With
     * Default: []
     */
    @SerialName("conflicts_with")
    val conflictsWith: List<String> = emptyList(),

    /**
     * Zero or more human-readable tags that describe OPTIONAL functionality described by this testcase.
     * Implementers should use this to specify testcases for non-mandatory X.509 behavior (like certificate
     * policy validation) or for 'pedantic' cases. Consumers that don't understand a given feature should
     * skip tests that are marked with it.
     *
     * Title: Features
     * Default: []
     */
    val features: List<Feature> = emptyList(),

    /**
     * The testcase's importance
     *
     * Default: undetermined
     */
    val importance: Importance = Importance.UNDETERMINED,

    /**
     * A short, Markdown-formatted description
     *
     * Title: Description
     */
    val description: String,

    /**
     * The kind of validation to perform
     */
    @SerialName("validation_kind")
    val validationKind: ValidationKind,

    /**
     * A list of PEM-encoded CA certificates to consider trusted
     *
     * Title: Trusted Certs
     */
    @SerialName("trusted_certs")
    val trustedCerts: List<String>,

    /**
     * A list of PEM-encoded untrusted intermediates to use during path building
     *
     * Title: Untrusted Intermediates
     */
    @SerialName("untrusted_intermediates")
    val untrustedIntermediates: List<String>,

    /**
     * The PEM-encoded peer (EE) certificate
     *
     * Title: Peer Certificate
     */
    @SerialName("peer_certificate")
    val peerCertificate: String,

    /**
     * The PEM-encoded private key for the peer certificate, if present
     *
     * Title: Peer Certificate Key
     * Default: null
     */
    @SerialName("peer_certificate_key")
    val peerCertificateKey: String? = null,

    /**
     * The time at which to perform the validation
     *
     * Title: Validation Time
     * Format: date-time (RFC 3339). If you prefer type-safety, consider kotlinx.datetime.Instant with a custom serializer.
     * Default: null
     */
    @SerialName("validation_time")
    val validationTime: String? = null, // TODO: Instant?

    /**
     * A list of acceptable signature algorithms to constrain against
     *
     * Title: Signature Algorithms
     */
    @SerialName("signature_algorithms")
    val signatureAlgorithms: List<SignatureAlgorithm>,

    /**
     * A constraining list of key usages
     *
     * Title: Key Usage
     */
    @SerialName("key_usage")
    val keyUsage: List<KeyUsage>,

    /**
     * A constraining list of extended key usages, either in well-known form or as OIDs
     *
     * Title: Extended Key Usage
     */
    @SerialName("extended_key_usage")
    val extendedKeyUsage: List<KnownEKUs>,

    /**
     * The expected validation result
     */
    @SerialName("expected_result")
    val expectedResult: ExpectedResult,

    /**
     * For server (i.e. client-side) validation: the expected peer name, if any
     *
     * Default: null
     */
    @SerialName("expected_peer_name")
    val expectedPeerName: PeerName? = null,

    /**
     * For client (i.e. server-side) validation: the expected peer names
     *
     * Title: Expected Peer Names
     */
    @SerialName("expected_peer_names")
    val expectedPeerNames: List<PeerName>,

    /**
     * The maximum chain-building depth
     *
     * Title: Max Chain Depth
     * Default: null
     */
    @SerialName("max_chain_depth")
    val maxChainDepth: Int? = null,

    /**
     * A list of PEM-encoded Certificate Revocation Lists (CRLs)
     *
     * Title: CRLs
     * Default: []
     */
    val crls: List<String> = emptyList(),
)

/**
 * Represents a peer (i.e., end entity) certificate's name (Subject or SAN).
 *
 * Title: PeerName
 */
@Serializable
data class PeerName(
    /**
     * The kind of peer name
     */
    val kind: PeerKind,

    /**
     * The peer's name
     *
     * Title: Value
     */
    val value: String,
)

/**
 * Different types of peer subjects.
 *
 * Title: PeerKind
 */
@Serializable
enum class PeerKind {
    /** JSON value: "RFC822" */
    @SerialName("RFC822")
    RFC822,

    /** JSON value: "DNS" */
    @SerialName("DNS")
    DNS,

    /** JSON value: "IP" */
    @SerialName("IP")
    IP
}

/**
 * Feature tags for testcases.
 *
 * Title: Feature
 */
@Serializable
enum class Feature {
    /** JSON value: "has-policy-constraints" */
    @SerialName("has-policy-constraints")
    HAS_POLICY_CONSTRAINTS,

    /** JSON value: "has-cert-policies" */
    @SerialName("has-cert-policies")
    HAS_CERT_POLICIES,

    /** JSON value: "no-cert-policies" */
    @SerialName("no-cert-policies")
    NO_CERT_POLICIES,

    /** JSON value: "pedantic-public-suffix-wildcard" */
    @SerialName("pedantic-public-suffix-wildcard")
    PEDANTIC_PUBLIC_SUFFIX_WILDCARD,

    /** JSON value: "name-constraint-dn" */
    @SerialName("name-constraint-dn")
    NAME_CONSTRAINT_DN,

    /** JSON value: "pedantic-webpki-subscriber-key" */
    @SerialName("pedantic-webpki-subscriber-key")
    PEDANTIC_WEBPKI_SUBSCRIBER_KEY,

    /** JSON value: "pedantic-webpki-eku" */
    @SerialName("pedantic-webpki-eku")
    PEDANTIC_WEBPKI_EKU,

    /** JSON value: "pedantic-serial-number" */
    @SerialName("pedantic-serial-number")
    PEDANTIC_SERIAL_NUMBER,

    /** JSON value: "max-chain-depth" */
    @SerialName("max-chain-depth")
    MAX_CHAIN_DEPTH,

    /** JSON value: "pedantic-rfc5280" */
    @SerialName("pedantic-rfc5280")
    PEDANTIC_RFC5280,

    /** JSON value: "rfc5280-incompatible-with-webpki" */
    @SerialName("rfc5280-incompatible-with-webpki")
    RFC5280_INCOMPATIBLE_WITH_WEBPKI,

    /** JSON value: "denial-of-service" */
    @SerialName("denial-of-service")
    DENIAL_OF_SERVICE,

    /** JSON value: "has-crl" */
    @SerialName("has-crl")
    HAS_CRL
}

/**
 * A subjective ranking of a testcase's importance.
 *
 * Title: Importance
 */
@Serializable
enum class Importance {
    /** JSON value: "undetermined" */
    @SerialName("undetermined")
    UNDETERMINED,

    /** JSON value: "low" */
    @SerialName("low")
    LOW,

    /** JSON value: "medium" */
    @SerialName("medium")
    MEDIUM,

    /** JSON value: "high" */
    @SerialName("high")
    HIGH,

    /** JSON value: "critical" */
    @SerialName("critical")
    CRITICAL
}

/**
 * The kind of validation to perform.
 *
 * Title: ValidationKind
 */
@Serializable
enum class ValidationKind {
    /** JSON value: "CLIENT" */
    @SerialName("CLIENT")
    CLIENT,

    /** JSON value: "SERVER" */
    @SerialName("SERVER")
    SERVER
}

/**
 * Valid X.509 signature algorithms.
 *
 * Title: SignatureAlgorithm
 */
@Serializable
enum class SignatureAlgorithm {
    /** JSON value: "RSA_WITH_MD5" */
    @SerialName("RSA_WITH_MD5")
    RSA_WITH_MD5,

    /** JSON value: "RSA_WITH_SHA1" */
    @SerialName("RSA_WITH_SHA1")
    RSA_WITH_SHA1,

    /** JSON value: "RSA_WITH_SHA224" */
    @SerialName("RSA_WITH_SHA224")
    RSA_WITH_SHA224,

    /** JSON value: "RSA_WITH_SHA256" */
    @SerialName("RSA_WITH_SHA256")
    RSA_WITH_SHA256,

    /** JSON value: "RSA_WITH_SHA384" */
    @SerialName("RSA_WITH_SHA384")
    RSA_WITH_SHA384,

    /** JSON value: "RSA_WITH_SHA512" */
    @SerialName("RSA_WITH_SHA512")
    RSA_WITH_SHA512,

    /** JSON value: "RSA_WITH_SHA3_224" */
    @SerialName("RSA_WITH_SHA3_224")
    RSA_WITH_SHA3_224,

    /** JSON value: "RSA_WITH_SHA3_256" */
    @SerialName("RSA_WITH_SHA3_256")
    RSA_WITH_SHA3_256,

    /** JSON value: "RSA_WITH_SHA3_384" */
    @SerialName("RSA_WITH_SHA3_384")
    RSA_WITH_SHA3_384,

    /** JSON value: "RSA_WITH_SHA3_512" */
    @SerialName("RSA_WITH_SHA3_512")
    RSA_WITH_SHA3_512,

    /** JSON value: "RSASSA_PSS" */
    @SerialName("RSASSA_PSS")
    RSASSA_PSS,

    /** JSON value: "ECDSA_WITH_SHA1" */
    @SerialName("ECDSA_WITH_SHA1")
    ECDSA_WITH_SHA1,

    /** JSON value: "ECDSA_WITH_SHA224" */
    @SerialName("ECDSA_WITH_SHA224")
    ECDSA_WITH_SHA224,

    /** JSON value: "ECDSA_WITH_SHA256" */
    @SerialName("ECDSA_WITH_SHA256")
    ECDSA_WITH_SHA256,

    /** JSON value: "ECDSA_WITH_SHA384" */
    @SerialName("ECDSA_WITH_SHA384")
    ECDSA_WITH_SHA384,

    /** JSON value: "ECDSA_WITH_SHA512" */
    @SerialName("ECDSA_WITH_SHA512")
    ECDSA_WITH_SHA512,

    /** JSON value: "ECDSA_WITH_SHA3_224" */
    @SerialName("ECDSA_WITH_SHA3_224")
    ECDSA_WITH_SHA3_224,

    /** JSON value: "ECDSA_WITH_SHA3_256" */
    @SerialName("ECDSA_WITH_SHA3_256")
    ECDSA_WITH_SHA3_256,

    /** JSON value: "ECDSA_WITH_SHA3_384" */
    @SerialName("ECDSA_WITH_SHA3_384")
    ECDSA_WITH_SHA3_384,

    /** JSON value: "ECDSA_WITH_SHA3_512" */
    @SerialName("ECDSA_WITH_SHA3_512")
    ECDSA_WITH_SHA3_512,

    /** JSON value: "DSA_WITH_SHA1" */
    @SerialName("DSA_WITH_SHA1")
    DSA_WITH_SHA1,

    /** JSON value: "DSA_WITH_SHA224" */
    @SerialName("DSA_WITH_SHA224")
    DSA_WITH_SHA224,

    /** JSON value: "DSA_WITH_SHA256" */
    @SerialName("DSA_WITH_SHA256")
    DSA_WITH_SHA256,

    /** JSON value: "DSA_WITH_SHA384" */
    @SerialName("DSA_WITH_SHA384")
    DSA_WITH_SHA384,

    /** JSON value: "DSA_WITH_SHA512" */
    @SerialName("DSA_WITH_SHA512")
    DSA_WITH_SHA512,

    /** JSON value: "ED25519" */
    @SerialName("ED25519")
    ED25519,

    /** JSON value: "ED448" */
    @SerialName("ED448")
    ED448,

    /** JSON value: "GOSTR3411_94_WITH_3410_2001" */
    @SerialName("GOSTR3411_94_WITH_3410_2001")
    GOSTR3411_94_WITH_3410_2001,

    /** JSON value: "GOSTR3410_2012_WITH_3411_2012_256" */
    @SerialName("GOSTR3410_2012_WITH_3411_2012_256")
    GOSTR3410_2012_WITH_3411_2012_256,

    /** JSON value: "GOSTR3410_2012_WITH_3411_2012_512" */
    @SerialName("GOSTR3410_2012_WITH_3411_2012_512")
    GOSTR3410_2012_WITH_3411_2012_512
}

/**
 * X.509 key usages.
 *
 * See: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
 *
 * Title: KeyUsage
 */
@Serializable
enum class KeyUsage {
    /** JSON value: "digitalSignature" */
    @SerialName("digitalSignature")
    DIGITAL_SIGNATURE,

    /** JSON value: "contentCommitment" */
    @SerialName("contentCommitment")
    CONTENT_COMMITMENT,

    /** JSON value: "keyEncipherment" */
    @SerialName("keyEncipherment")
    KEY_ENCIPHERMENT,

    /** JSON value: "dataEncipherment" */
    @SerialName("dataEncipherment")
    DATA_ENCIPHERMENT,

    /** JSON value: "keyAgreement" */
    @SerialName("keyAgreement")
    KEY_AGREEMENT,

    /** JSON value: "keyCertSign" */
    @SerialName("keyCertSign")
    KEY_CERT_SIGN,

    /** JSON value: "cRLSign" */
    @SerialName("cRLSign")
    CRL_SIGN,

    /** JSON value: "encipherOnly" */
    @SerialName("encipherOnly")
    ENCIPHER_ONLY,

    /** JSON value: "decipherOnly" */
    @SerialName("decipherOnly")
    DECIPHER_ONLY
}

/**
 * Well-known extended key usages, from RFC 5280.
 *
 * See: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12
 *
 * Title: KnownEKUs
 */
@Serializable
enum class KnownEKUs {
    /** JSON value: "anyExtendedKeyUsage" */
    @SerialName("anyExtendedKeyUsage")
    ANY_EXTENDED_KEY_USAGE,

    /** JSON value: "serverAuth" */
    @SerialName("serverAuth")
    SERVER_AUTH,

    /** JSON value: "clientAuth" */
    @SerialName("clientAuth")
    CLIENT_AUTH,

    /** JSON value: "codeSigning" */
    @SerialName("codeSigning")
    CODE_SIGNING,

    /** JSON value: "emailProtection" */
    @SerialName("emailProtection")
    EMAIL_PROTECTION,

    /** JSON value: "timeStamping" */
    @SerialName("timeStamping")
    TIME_STAMPING,

    /** JSON value: "OCSPSigning" */
    @SerialName("OCSPSigning")
    OCSP_SIGNING
}

/**
 * Represents an expected testcase evaluation result.
 *
 * Title: ExpectedResult
 */
@Serializable
enum class ExpectedResult {
    /** JSON value: "SUCCESS" */
    @SerialName("SUCCESS")
    SUCCESS,

    /** JSON value: "FAILURE" */
    @SerialName("FAILURE")
    FAILURE
}
