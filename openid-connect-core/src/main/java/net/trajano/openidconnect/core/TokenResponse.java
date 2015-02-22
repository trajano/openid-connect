package net.trajano.openidconnect.core;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

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

    public String getAccessToken() {

        return accessToken;
    }

    public void setAccessToken(String accessToken) {

        this.accessToken = accessToken;
    }

    public String getTokenType() {

        return tokenType;
    }

    public void setTokenType(String tokenType) {

        this.tokenType = tokenType;
    }

    public int getExpiresIn() {

        return expiresIn;
    }

    public void setExpiresIn(int expiresIn) {

        this.expiresIn = expiresIn;
    }

    public String getScope() {

        return scope;
    }

    public void setScope(String scope) {

        this.scope = scope;
    }

    public String getState() {

        return state;
    }

    public void setState(String state) {

        this.state = state;
    }

    public String getIdToken() {

        return idToken;
    }

    public void setIdToken(String idToken) {

        this.idToken = idToken;
    }

    /**
     * ID Token value associated with the authenticated session.
     */
    @XmlElement(name = "id_token", required = true)
    private String idToken;
}
