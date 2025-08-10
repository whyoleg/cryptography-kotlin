/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.pem

import kotlin.jvm.*

/**
 * Represents PEM encapsulation label as defined by [RFC 7468](https://datatracker.ietf.org/doc/html/rfc7468).
 * Primarily used by [PemDocument] as the document's [label][PemDocument.label]
 *
 * The label is used verbatim in the PEM boundaries and is matched case-sensitively.
 * The [value] is treated as-is, no normalization or validation is performed
 *
 * @property value Case-sensitive text placed between BEGIN/END boundaries of the PEM document
 */
@JvmInline
public value class PemLabel(public val value: String) {
    public companion object {
        /**
         * Represents a label used in PEM documents that contain
         * DER encoded ASN.1 `SubjectPublicKeyInfo` structure
         * as described in [Section 4.1.2.7 of RFC5280](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.7)
         */
        public val PublicKey: PemLabel = PemLabel("PUBLIC KEY")

        /**
         * Represents a label used in PEM documents that contain
         * DER encoded ASN.1 `PrivateKeyInfo` structure
         * as described in [RFC5208, known as PKCS#8](https://datatracker.ietf.org/doc/html/rfc5208)
         */
        public val PrivateKey: PemLabel = PemLabel("PRIVATE KEY")

        /**
         * Represents a label used in PEM documents that contain
         * DER encoded ASN.1 `EncryptedPrivateKeyInfo` structure
         * as described in [RFC5208, known as PKCS#8](https://datatracker.ietf.org/doc/html/rfc5208)
         */
        public val EncryptedPrivateKey: PemLabel = PemLabel("ENCRYPTED PRIVATE KEY")

        /**
         * Represents a label used in PEM documents that contain
         * DER encoded ASN.1 `RSAPublicKey` structure
         * as described in [Appendix A.1.1 of RFC8017, known as PKCS#1](https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.1)
         */
        public val RsaPublicKey: PemLabel = PemLabel("RSA PUBLIC KEY")

        /**
         * Represents a label used in PEM documents that contain
         * DER encoded ASN.1 `RSAPrivateKey` structure
         * as described in [Appendix A.1.2 of RFC8017, known as PKCS#1](https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.2)
         */
        public val RsaPrivateKey: PemLabel = PemLabel("RSA PRIVATE KEY")

        /**
         * Represents a label used in PEM documents that contain
         * DER encoded ASN.1 `ECPrivateKey` structure
         * as described in [RFC5915](https://datatracker.ietf.org/doc/html/rfc5915) and [SEC1](https://www.secg.org/sec1-v2.pdf)
         */
        public val EcPrivateKey: PemLabel = PemLabel("EC PRIVATE KEY")

        /**
         * Represents a label used in PEM documents that contain
         * DER encoded ASN.1 `Certificate` structure
         * as described in [Section 4 of RFC5280](https://datatracker.ietf.org/doc/html/rfc5280#section-4)
         */
        public val Certificate: PemLabel = PemLabel("CERTIFICATE")

        /**
         * Represents a label used in PEM documents that contain
         * DER encoded ASN.1 `CertificationRequest` structure
         * as described in [RFC2986, known as PKCS#10](https://datatracker.ietf.org/doc/html/rfc2986)
         */
        public val CertificateRequest: PemLabel = PemLabel("CERTIFICATE REQUEST")
    }
}
