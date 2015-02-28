package net.trajano.openidconnect.provider;

import net.trajano.openidconnect.core.IdToken;
import net.trajano.openidconnect.core.TokenResponse;

public interface IdTokenProvider {

    TokenResponse getByCode(String code);

    TokenResponse store(IdToken idToken);

    TokenResponse getByAccessToken(String accessToken);
}
