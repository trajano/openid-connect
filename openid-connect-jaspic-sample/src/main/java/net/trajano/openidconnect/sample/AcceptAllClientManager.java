package net.trajano.openidconnect.sample;

import java.net.URI;

import net.trajano.openidconnect.servlet.ClientManager;

public class AcceptAllClientManager implements ClientManager {

    @Override
    public boolean isRedirectUriValidForClient(String clientId,
            URI redirectUri) {

        return true;
    }

    @Override
    public boolean authenticateClient(String clientId,
            String clientSecret) {

        return true;
    }

}
