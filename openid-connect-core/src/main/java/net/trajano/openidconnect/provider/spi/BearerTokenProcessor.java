package net.trajano.openidconnect.provider.spi;

import javax.ejb.Local;
import javax.servlet.http.HttpServletRequest;

import net.trajano.openidconnect.core.IdTokenResponse;

@Local
public interface BearerTokenProcessor {

    IdTokenResponse getToken(HttpServletRequest req);

    String validateAndGetClientId(HttpServletRequest request);

}
