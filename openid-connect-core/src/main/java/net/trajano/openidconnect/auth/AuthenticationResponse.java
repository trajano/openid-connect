package net.trajano.openidconnect.auth;


public class AuthenticationResponse {

    private String accessToken;

    private String code;

    private String encodedIdToken;

    private String state;

    private String tokenType;

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

}
