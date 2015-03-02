package net.trajano.openidconnect.token;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.xml.bind.annotation.XmlElement;

import net.trajano.openidconnect.core.Scope;

public class TokenResponse {

    public String getAccessToken() {

        return accessToken;
    }

    public void setAccessToken(String accessToken) {

        this.accessToken = accessToken;
    }

    public int getExpiresIn() {

        return expiresIn;
    }

    public void setExpiresIn(int expiresIn) {

        this.expiresIn = expiresIn;
    }

    public String getRefreshToken() {

        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {

        this.refreshToken = refreshToken;
    }

    public static final String BEARER = "Bearer";

    /**
     * REQUIRED. The access token issued by the authorization server.
     */
    @XmlElement(name = "access_token", required = true)
    private String accessToken;

    /**
     * RECOMMENDED. The lifetime in seconds of the access token. For example,
     * the value "3600" denotes that the access token will expire in one hour
     * from the time the response was generated. If omitted, the authorization
     * server SHOULD provide the expiration time via other means or document the
     * default value.
     */
    @XmlElement(name = "expires_in", required = false)
    private int expiresIn;

    @XmlElement(name = "refresh_token")
    private String refreshToken;

    public void setScope(final String scope) {

        this.scope = scope;
    }


    /**
     * OPTIONAL, if identical to the scope requested by the client; otherwise,
     * REQUIRED. The scope of the access token as described by Section 3.3.
     */
    private String scope;

    public String getScope() {

        return scope;
    }

    public void setTokenType(final String tokenType) {

        this.tokenType = tokenType;
    }

    public void setScopes(Set<Scope> scopes) {

        StringBuilder b = new StringBuilder();
        Iterator<Scope> i = scopes.iterator();
        b.append(i.next());
        while (i.hasNext()) {
            b.append(' ');
            b.append(i.next());
        }
        scope = b.toString();

    }

    public Set<Scope> getScopes() {

        Set<Scope> scopes = new HashSet<>();
        for (final String scopePart : scope.split("\\s")) {
            scopes.add(Scope.valueOf(scopePart));
        }
        return scopes;

    }

    public String getTokenType() {

        return tokenType;
    }

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
}
