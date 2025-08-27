/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.serialization.asn1.*
import kotlinx.serialization.*
import kotlin.jvm.*

//  Certificate  ::=  SEQUENCE  {
//        tbsCertificate       TBSCertificate,
//        signatureAlgorithm   AlgorithmIdentifier,
//        signatureValue       BIT STRING  }
//
//   TBSCertificate  ::=  SEQUENCE  {
//        version         [0]  EXPLICIT Version DEFAULT v1,
//        serialNumber         CertificateSerialNumber,
//        signature            AlgorithmIdentifier,
//        issuer               Name,
//        validity             Validity,
//        subject              Name,
//        subjectPublicKeyInfo SubjectPublicKeyInfo,
//        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
//                             -- If present, version MUST be v2 or v3
//        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
//                             -- If present, version MUST be v2 or v3
//        extensions      [3]  EXPLICIT Extensions OPTIONAL
//                             -- If present, version MUST be v3
//        }
//
//   Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
//
//   CertificateSerialNumber  ::=  INTEGER
//
//   Validity ::= SEQUENCE {
//        notBefore      Time,
//        notAfter       Time }
//
//   Time ::= CHOICE {
//        utcTime        UTCTime,
//        generalTime    GeneralizedTime }
//
//   UniqueIdentifier  ::=  BIT STRING
//
//   SubjectPublicKeyInfo  ::=  SEQUENCE  {
//        algorithm            AlgorithmIdentifier,
//        subjectPublicKey     BIT STRING  }
//
//   Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
//
//   Extension  ::=  SEQUENCE  {
//        extnID      OBJECT IDENTIFIER,
//        critical    BOOLEAN DEFAULT FALSE,
//        extnValue   OCTET STRING
//                    -- contains the DER encoding of an ASN.1 value
//                    -- corresponding to the extension type identified
//                    -- by extnID
//        }


// Instant -> GeneralizedTime | UTCTime | DATE


//private sealed class TimeX {
//    value class utc(@Asn1UTCTime val time: Instant) : TimeX()
//    value class general(@Asn1GeneralizedTime val time: Instant) : TimeX()
//}

//Certificate  ::=  SEQUENCE  {
//        tbsCertificate       TBSCertificate,
//        signatureAlgorithm   AlgorithmIdentifier,
//        signatureValue       BIT STRING  }
@Serializable
public data class Certificate(
    public val tbsCertificate: TbsCertificate,
    public val signatureAlgorithm: AlgorithmIdentifier,
    public val signatureValue: BitArray,
)

//   TBSCertificate  ::=  SEQUENCE  {
//        version         [0]  EXPLICIT Version DEFAULT v1,
//        serialNumber         CertificateSerialNumber,
//        signature            AlgorithmIdentifier,
//        issuer               Name,
//        validity             Validity,
//        subject              Name,
//        subjectPublicKeyInfo SubjectPublicKeyInfo,
//        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
//                             -- If present, version MUST be v2 or v3
//        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
//                             -- If present, version MUST be v2 or v3
//        extensions      [3]  EXPLICIT Extensions OPTIONAL
//                             -- If present, version MUST be v3
//        }
//
@Serializable
public data class TbsCertificate(
    @ContextSpecificTag(0, ContextSpecificTag.TagType.EXPLICIT)
    public val version: Int = 0, // TODO EXPLICIT?
    public val serialNumber: CertificateSerialNumber,
    public val signature: AlgorithmIdentifier,
    public val issuer: Name,
    public val validity: Validity,
    public val subject: Name,
    public val subjectPublicKeyInfo: SubjectPublicKeyInfo,
    @ContextSpecificTag(1, ContextSpecificTag.TagType.IMPLICIT)
    public val issuerUniqueID: UniqueIdentifier? = null,
    @ContextSpecificTag(2, ContextSpecificTag.TagType.IMPLICIT)
    public val subjectUniqueID: UniqueIdentifier? = null,
    @ContextSpecificTag(3, ContextSpecificTag.TagType.EXPLICIT)
    public val extensions: Extensions? = null,
)

public typealias CertificateSerialNumber = BigInt

@Serializable
public data class Validity(
    public val notBefore: Time,
    public val notAfter: Time,
)

// TODO!!!
@Serializable
public data class Time(
    public val utcTime: String? = null,
    public val generalTime: String? = null,
)

public typealias UniqueIdentifier = BitArray

public typealias Extensions = List<Extension>

@Serializable
public data class Extension(
    public val extnID: ObjectIdentifier,
    public val critical: Boolean = false,
    public val extnValue: ByteArray,
)

@Serializable
@JvmInline
public value class Name(
    public val s: String, // TODO!!!
)

//Name ::= CHOICE { -- only one possibility for now --
//    rdnSequence  RDNSequence }
//
//RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
//
//RelativeDistinguishedName ::=
//SET SIZE (1..MAX) OF AttributeTypeAndValue
//
//AttributeTypeAndValue ::= SEQUENCE {
//    type     AttributeType,
//    value    AttributeValue }
//
//AttributeType ::= OBJECT IDENTIFIER
//
//AttributeValue ::= ANY -- DEFINED BY AttributeType
//
//DirectoryString ::= CHOICE {
//    teletexString           TeletexString (SIZE (1..MAX)),
//    printableString         PrintableString (SIZE (1..MAX)),
//    universalString         UniversalString (SIZE (1..MAX)),
//    utf8String              UTF8String (SIZE (1..MAX)),
//    bmpString               BMPString (SIZE (1..MAX)) }
