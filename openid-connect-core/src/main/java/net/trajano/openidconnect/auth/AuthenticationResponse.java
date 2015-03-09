package net.trajano.openidconnect.auth;

import java.net.URI;

import javax.xml.bind.annotation.XmlTransient;

public class AuthenticationResponse {

    private String accessToken;

    private String code;

    private String encodedIdToken;

    private String state;

    private String tokenType;

    @XmlTransient
    private URI redirectUri;

    @XmlTransient
    private ResponseMode responseMode;

    public URI getRedirectUri() {

        return redirectUri;
    }

    public void setRedirectUri(URI redirectUri) {

        this.redirectUri = redirectUri;
    }

    public String getAccessToken() {

        return accessToken;
    }

    public String getCode() {

        return code;
    }

    public String getEncodedIdToken() {

        return encodedIdToken;
    }

    public String getState() {

        return state;
    }

    public String getTokenType() {

        return tokenType;
    }

    public void setAccessToken(final String tokenType,
            final String accessToken) {

        this.tokenType = tokenType;
        this.accessToken = accessToken;

    }

    public void setCode(final String code) {

        this.code = code;
    }

    public void setEncodedIdToken(final String encodedIdToken) {

        this.encodedIdToken = encodedIdToken;
    }

    public void setState(final String state) {

        this.state = state;
    }

    public ResponseMode getResponseMode() {

        return responseMode;
    }

    public void setResponseMode(ResponseMode responseMode) {

        this.responseMode = responseMode;

    }

}
