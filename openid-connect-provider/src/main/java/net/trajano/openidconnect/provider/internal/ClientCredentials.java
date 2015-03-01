package net.trajano.openidconnect.provider.internal;

public class ClientCredentials {

    public ClientCredentials(String clientId, String clientSecret) {

        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    private final String clientId;

    public String getClientId() {

        return clientId;
    }

    public String getClientSecret() {

        return clientSecret;
    }

    private final String clientSecret;
}
