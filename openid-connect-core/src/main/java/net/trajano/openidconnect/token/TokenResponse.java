package net.trajano.openidconnect.token;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.json.JsonObject;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlTransient;

import net.trajano.openidconnect.core.Scope;

@XmlAccessorType(XmlAccessType.NONE)
public class TokenResponse implements
    Serializable {

    public static final String BEARER = "Bearer";

    /**
     *
     */
    private static final long serialVersionUID = 5216911835177655318L;

    /**
     * REQUIRED. The access token issued by the authorization server.
     */
    @XmlElement(name = "access_token",
        required = true)
    private String accessToken;

    /**
     * RECOMMENDED. The lifetime in seconds of the access token. For example,
     * the value "3600" denotes that the access token will expire in one hour
     * from the time the response was generated. If omitted, the authorization
     * server SHOULD provide the expiration time via other means or document the
     * default value.
     */
    @XmlElement(name = "expires_in",
        required = false)
    private int expiresIn;

    @XmlElement(name = "refresh_token")
    private String refreshToken;

    /**
     * OPTIONAL, if identical to the scope requested by the client; otherwise,
     * REQUIRED. The scope of the access token as described by Section 3.3.
     */
    @XmlElement(name = "scope")
    private String scope;

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
    @XmlElement(name = "token_type",
        required = true)
    private String tokenType = BEARER;

    /**
     * Constructs TokenResponse.
     *
     * @param tokenResponse
     */
    public TokenResponse() {
    }

    /**
     * Constructs TokenResponse.
     *
     * @param tokenResponse
     */
    public TokenResponse(final JsonObject tokenResponse) {
        accessToken = tokenResponse.getString("access_token");
        expiresIn = tokenResponse.getInt("expires_in");
        if (tokenResponse.containsKey("refresh_token")) {
            refreshToken = tokenResponse.getString("refresh_token");
        }
        if (tokenResponse.containsKey("scope")) {
            scope = tokenResponse.getString("scope");
        }
        tokenType = tokenResponse.getString("token_type", BEARER);
    }

    public String getAccessToken() {

        return accessToken;
    }

    public int getExpiresIn() {

        return expiresIn;
    }

    public String getRefreshToken() {

        return refreshToken;
    }

    public String getScope() {

        return scope;
    }

    @XmlTransient
    public Set<Scope> getScopes() {

        final Set<Scope> scopes = new HashSet<>();
        for (final String scopePart : scope.split("\\s")) {
            scopes.add(Scope.valueOf(scopePart));
        }
        return scopes;

    }

    public String getTokenType() {

        return tokenType;
    }

    public void setAccessToken(final String accessToken) {

        this.accessToken = accessToken;
    }

    public void setExpiresIn(final int expiresIn) {

        this.expiresIn = expiresIn;
    }

    public void setRefreshToken(final String refreshToken) {

        this.refreshToken = refreshToken;
    }

    public void setScope(final String scope) {

        this.scope = scope;
    }

    public void setScopes(final Set<Scope> scopes) {

        final StringBuilder b = new StringBuilder();
        final Iterator<Scope> i = scopes.iterator();
        b.append(i.next());
        while (i.hasNext()) {
            b.append(' ');
            b.append(i.next());
        }
        scope = b.toString();

    }

    public void setTokenType(final String tokenType) {

        this.tokenType = tokenType;
    }
}
