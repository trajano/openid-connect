package net.trajano.openidconnect.token;

import java.io.Serializable;
import java.util.Date;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import net.trajano.openidconnect.userinfo.Userinfo;

/**
 * <p>
 * ID Token. The primary extension that OpenID Connect makes to OAuth 2.0 to
 * enable End-Users to be Authenticated is the ID Token data structure. The ID
 * Token is a security token that contains Claims about the Authentication of an
 * End-User by an Authorization Server when using a Client, and potentially
 * other requested Claims. The ID Token is represented as a JSON Web Token
 * (JWT).
 * </p>
 * <p>
 * ID Tokens MAY contain other Claims. Any Claims used that are not understood
 * MUST be ignored. See Sections 3.1.3.6, 3.3.2.11, 5.1, and 7.4 for additional
 * Claims defined by this specification.
 * </p>
 * <p>
 * ID Tokens MUST be signed using JWS [JWS] and optionally both signed and then
 * encrypted using JWS [JWS] and JWE [JWE] respectively, thereby providing
 * authentication, integrity, non-repudiation, and optionally, confidentiality,
 * per Section 16.14. If the ID Token is encrypted, it MUST be signed then
 * encrypted, with the result being a Nested JWT, as defined in [JWT]. ID Tokens
 * MUST NOT use none as the alg value unless the Response Type used returns no
 * ID Token from the Authorization Endpoint (such as when using the
 * Authorization Code Flow) and the Client explicitly requested the use of none
 * at Registration time.
 * </p>
 * <p>
 * ID Tokens SHOULD NOT use the JWS or JWE x5u, x5c, jku, or jwk Header
 * Parameter fields. Instead, references to keys used are communicated in
 * advance using Discovery and Registration parameters, per Section 10.
 * </p>
 * <p>
 * This extends {@link Userinfo} as per
 * http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims which
 * indicates that the claims can be stored in the token as well.
 * </p>
 * 
 * @author Archimedes Token
 * @see http://openid.net/specs/openid-connect-core-1_0.html#IDToken
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class IdToken extends Userinfo implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = -6920223034971350418L;

    /**
     * OPTIONAL. Authentication Context Class Reference. String specifying an
     * Authentication Context Class Reference value that identifies the
     * Authentication Context Class that the authentication performed satisfied.
     * The value "0" indicates the End-User authentication did not meet the
     * requirements of ISO/IEC 29115 [ISO29115] level 1. Authentication using a
     * long-lived browser cookie, for instance, is one example where the use of
     * "level 0" is appropriate. Authentications with level 0 SHOULD NOT be used
     * to authorize access to any resource of any monetary value. (This
     * corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] nist_auth_level 0.) An
     * absolute URI or an RFC 6711 [RFC6711] registered name SHOULD be used as
     * the acr value; registered names MUST NOT be used with a different meaning
     * than that which is registered. Parties using this claim will need to
     * agree upon the meanings of the values used, which may be
     * context-specific. The acr value is a case sensitive string.
     */
    private String acr;

    /**
     * OPTIONAL. Authentication Methods References. JSON array of strings that
     * are identifiers for authentication methods used in the authentication.
     * For instance, values might indicate that both password and OTP
     * authentication methods were used. The definition of particular values to
     * be used in the amr Claim is beyond the scope of this specification.
     * Parties using this claim will need to agree upon the meanings of the
     * values used, which may be context-specific. The amr value is an array of
     * case sensitive strings.
     */
    private String[] amr;

    @XmlElement(name = "at_hash")
    private String atHash;

    /**
     * REQUIRED. Audience(s) that this ID Token is intended for. It MUST contain
     * the OAuth 2.0 client_id of the Relying Party as an audience value. It MAY
     * also contain identifiers for other audiences. In the general case, the
     * aud value is an array of case sensitive strings. In the common special
     * case when there is one audience, the aud value MAY be a single case
     * sensitive string.
     */
    @XmlElement(required = true)
    private String aud;

    /**
     * Time when the End-User authentication occurred. Its value is a JSON
     * number representing the number of seconds from 1970-01-01T0:0:0Z as
     * measured in UTC until the date/time. When a max_age request is made or
     * when auth_time is requested as an Essential Claim, then this Claim is
     * REQUIRED; otherwise, its inclusion is OPTIONAL. (The auth_time Claim
     * semantically corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] auth_time
     * response parameter.)
     */
    @XmlElement(name = "auth_time")
    private long authTime;

    /**
     * OPTIONAL. Authorized party - the party to which the ID Token was issued.
     * If present, it MUST contain the OAuth 2.0 Client ID of this party. This
     * Claim is only needed when the ID Token has a single audience value and
     * that audience is different than the authorized party. It MAY be included
     * even when the authorized party is the same as the sole audience. The azp
     * value is a case sensitive string containing a StringOrURI value.
     */
    private String azp;

    /**
     * REQUIRED. Expiration time on or after which the ID Token MUST NOT be
     * accepted for processing. The processing of this parameter requires that
     * the current date/time MUST be before the expiration date/time listed in
     * the value. Implementers MAY provide for some small leeway, usually no
     * more than a few minutes, to account for clock skew. Its value is a JSON
     * number representing the number of seconds from 1970-01-01T0:0:0Z as
     * measured in UTC until the date/time. See RFC 3339 [RFC3339] for details
     * regarding date/times in general and UTC in particular.
     */
    @XmlElement(required = true)
    private long exp;

    /**
     * REQUIRED. Time at which the JWT was issued. Its value is a JSON number
     * representing the number of seconds from 1970-01-01T0:0:0Z as measured in
     * UTC until the date/time.
     */
    @XmlElement(required = true)
    private long iat;

    /**
     * REQUIRED. Issuer Identifier for the Issuer of the response. The iss value
     * is a case sensitive URL using the https scheme that contains scheme,
     * host, and optionally, port number and path components and no query or
     * fragment components.
     */
    @XmlElement(required = true)
    private String iss;

    /**
     * String value used to associate a Client session with an ID Token, and to
     * mitigate replay attacks. The value is passed through unmodified from the
     * Authentication Request to the ID Token. If present in the ID Token,
     * Clients MUST verify that the nonce Claim Value is equal to the value of
     * the nonce parameter sent in the Authentication Request. If present in the
     * Authentication Request, Authorization Servers MUST include a nonce Claim
     * in the ID Token with the Claim Value being the nonce value sent in the
     * Authentication Request. Authorization Servers SHOULD perform no other
     * processing on nonce values used. The nonce value is a case sensitive
     * string.
     */
    private String nonce;

    /**
     * REQUIRED. Subject Identifier. A locally unique and never reassigned
     * identifier within the Issuer for the End-User, which is intended to be
     * consumed by the Client, e.g., 24400320 or
     * AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4. It MUST NOT exceed 255 ASCII
     * characters in length. The sub value is a case sensitive string.
     */
    @XmlElement(required = true)
    private String sub;

    public String getAcr() {

        return acr;
    }

    public String[] getAmr() {

        return amr;
    }

    public String getAtHash() {

        return atHash;
    }

    public String getAud() {

        return aud;
    }

    public long getAuthTime() {

        return authTime;
    }

    public String getAzp() {

        return azp;
    }

    public long getExp() {

        return exp;
    }

    /**
     * Returns the timestamp when the token will expire.
     *
     * @return
     */
    public Date getExpiration() {

        return new Date(exp * 1000L);
    }

    public long getIat() {

        return iat;
    }

    public String getIss() {

        return iss;
    }

    /**
     * Returns the timestamp the token was issued on.
     *
     * @return
     */
    public Date getIssuedOn() {

        return new Date(iat * 1000L);
    }

    public String getNonce() {

        return nonce;
    }

    public String getSub() {

        return sub;
    }

    /**
     * Checks if the exp value before or after the current time.
     *
     * @return true if the current time is after exp.
     */
    public boolean isExpired() {

        return System.currentTimeMillis() / 1000 > exp;
    }

    /**
     * Sets the Issuing time and the expiration values based on the current time
     * and expiration specified.
     *
     * @param expirationInSeconds
     */

    public void resetIssueAndExpiration(final int expirationInSeconds) {

        iat = System.currentTimeMillis() / 1000;
        exp = iat + expirationInSeconds;
    }

    public void setAcr(final String acr) {

        this.acr = acr;
    }

    public void setAmr(final String[] amr) {

        this.amr = amr;
    }

    public void setAtHash(final String atHash) {

        this.atHash = atHash;
    }

    public void setAud(final String aud) {

        this.aud = aud;
    }

    public void setAuthTime(final long authTime) {

        this.authTime = authTime;
    }

    public void setAzp(final String azp) {

        this.azp = azp;
    }

    public void setExp(final long exp) {

        this.exp = exp;
    }

    public void setIat(final long iat) {

        this.iat = iat;
    }

    public void setIss(final String iss) {

        this.iss = iss;
    }

    public void setNonce(final String nonce) {

        this.nonce = nonce;
    }

    public void setSub(final String sub) {

        this.sub = sub;
    }
}
