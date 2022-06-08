package dev.whyoleg.jose

public class JsonWebToken(
    public val header: Header,
    public val payload: Payload,
    public val signature: String //base64url
) {

    //TODO: sealed or abstract?
    public class Header(
        public val algorithm: Algorithm,
        public val type: String, //TODO
        public val contentType: String //TODO
    ) {
        public sealed class Algorithm(public val value: String) {
            public object HS256 : Algorithm("HS256")
            public object RS256 : Algorithm("RS256")
            public object ES256 : Algorithm("ES256")
        }
    }

    public class Payload(
        public val issuer: String?,
        public val subject: String?,
        public val audience: String?,
        public val expiresAt: Long?, //TODO: kotlinx.datetime
        public val notBefore: Long?, //TODO: kotlinx.datetime
        public val issuedAt: Long?, //TODO: kotlinx.datetime,
        public val jwtId: String? //TODO: type?
    )
}
