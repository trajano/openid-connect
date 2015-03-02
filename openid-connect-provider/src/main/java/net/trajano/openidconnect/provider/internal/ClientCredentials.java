package net.trajano.openidconnect.provider.internal;

public class ClientCredentials {

    private final String clientId;

    private final String clientSecret;

    public ClientCredentials(final String clientId, final String clientSecret) {

        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public String getClientId() {

        return clientId;
    }

    public String getClientSecret() {

        return clientSecret;
    }
}
