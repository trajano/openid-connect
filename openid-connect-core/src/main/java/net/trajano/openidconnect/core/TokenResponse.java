package net.trajano.openidconnect.core;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Map;

import javax.ws.rs.core.MediaType;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import net.trajano.openidconnect.crypto.JwtUtil;

/**
 * <p>
 * Access Token Response.
 * </p>
 * <p>
 * After receiving and validating a valid and authorized Token Request from the
 * Client, the Authorization Server returns a successful response that includes
 * an ID Token and an Access Token. The parameters in the successful response
 * are defined in Section 4.1.4 of OAuth 2.0 [RFC6749]. The response uses the
 * application/json media type.
 * </p>
 * <p>
 * The OAuth 2.0 token_type response parameter value MUST be Bearer, as
 * specified in OAuth 2.0 Bearer Token Usage [RFC6750], unless another Token
 * Type has been negotiated with the Client. Servers SHOULD support the Bearer
 * Token Type; use of other Token Types is outside the scope of this
 * specification.
 * </p>
 * <p>
 * All Token Responses that contain tokens, secrets, or other sensitive
 * information MUST include the following HTTP response header fields and
 * values:
 * <table>
 * <tr>
 * <th>Header Name</th>
 * <th>Header Value</th>
 * </tr>
 * <tr>
 * <td>Cache-Control</td>
 * <td>no-store</td>
 * </tr>
 * <tr>
 * <td>Pragma</td>
 * <td>no-cache</td>
 * </tr>
 * </table>
 *
 * @see http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
 * @see http://tools.ietf.org/html/rfc6749#section-4.2.2
 * @author Archimedes
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class TokenResponse {

    public static final String BEARER = "Bearer";

    /**
     * REQUIRED. The access token issued by the authorization server.
     */
    @XmlElement(name = "access_token", required = true)
    private String accessToken;

    /**
     * Encoded ID Token value associated with the authenticated session.
     */
    @XmlElement(name = "id_token", required = true)
    private String encodedIdToken;

    /**
     * RECOMMENDED. The lifetime in seconds of the access token. For example,
     * the value "3600" denotes that the access token will expire in one hour
     * from the time the response was generated. If omitted, the authorization
     * server SHOULD provide the expiration time via other means or document the
     * default value.
     */
    @XmlElement(name = "expires_in", required = false)
    private int expiresIn;

    /**
     * OPTIONAL, if identical to the scope requested by the client; otherwise,
     * REQUIRED. The scope of the access token as described by Section 3.3.
     */
    private String scope;

    /**
     * REQUIRED if the "state" parameter was present in the client authorization
     * request. The exact value received from the client.
     */
    private String state;

    /**
     * <p>
     * REQUIRED. The type of the token issued as described in Section 7.1. Value
     * is case insensitive.
     * </p>
     * <p>
     * The OAuth 2.0 token_type response parameter value MUST be Bearer, as
     * specified in OAuth 2.0 Bearer Token Usage [RFC6750], unless another Token
     * Type has been negotiated with the Client. Servers SHOULD support the
     * Bearer Token Type; use of other Token Types is outside the scope of this
     * specification.
     * </p>
     */
    @XmlElement(name = "token_type", required = true)
    private String tokenType = BEARER;

    public String getAccessToken() {

        return accessToken;
    }

    public String getEncodedIdToken() {

        return encodedIdToken;
    }

    public int getExpiresIn() {

        return expiresIn;
    }

    /**
     * Gets the ID Token without signature validation.
     *
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public IdToken getIdToken() throws IOException,
    GeneralSecurityException {

        return getIdToken(null);
    }

    /**
     * Gets the ID Token with signature validation.
     *
     * @param keyMap
     *            key map
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public IdToken getIdToken(final Map<String, Key> keyMap) throws IOException,
    GeneralSecurityException {

        return new IdTokenProvider().readFrom(IdToken.class, null, null, MediaType.APPLICATION_JSON_TYPE, null, new ByteArrayInputStream(JwtUtil.getJwsPayload(encodedIdToken, keyMap)));

    }

    public String getScope() {

        return scope;
    }

    public String getState() {

        return state;
    }

    public String getTokenType() {

        return tokenType;
    }

    public void setAccessToken(final String accessToken) {

        this.accessToken = accessToken;
    }

    public void setEncodedIdToken(final String encodedIdToken) throws GeneralSecurityException {

        this.encodedIdToken = encodedIdToken;
    }

    public void setExpiresIn(final int expiresIn) {

        this.expiresIn = expiresIn;
    }

    public void setScope(final String scope) {

        this.scope = scope;
    }

    public void setState(final String state) {

        this.state = state;
    }

    public void setTokenType(final String tokenType) {

        this.tokenType = tokenType;
    }
}
