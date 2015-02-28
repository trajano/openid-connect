package net.trajano.openidconnect.provider.internal;

import javax.ejb.Local;
import javax.servlet.http.HttpServletRequest;

import net.trajano.openidconnect.core.TokenResponse;

@Local
public interface BearerTokenProcessor {

    TokenResponse getToken(HttpServletRequest req);

    String validateAndGetClientId(HttpServletRequest request);

}
