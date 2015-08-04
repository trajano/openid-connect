package net.trajano.openidconnect.jaspic.internal.processors;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.security.auth.message.AuthStatus;
import javax.ws.rs.core.MediaType;

import net.trajano.openidconnect.jaspic.OpenIdConnectAuthModule;
import net.trajano.openidconnect.jaspic.internal.ValidateContext;
import net.trajano.openidconnect.jaspic.internal.ValidateRequestProcessor;

public class IdTokenRequestProcessor implements ValidateRequestProcessor {

    @Override
    public boolean canValidateRequest(final ValidateContext context) {

        if (!context.hasTokenCookie()) {
            return false;
        }

        return context.isSecure() && context.isGetRequest() && context.isRequestUri(OpenIdConnectAuthModule.TOKEN_URI_KEY);
    }

    @Override
    public AuthStatus validateRequest(final ValidateContext context) throws IOException,
        GeneralSecurityException {

        context.setContentType(MediaType.APPLICATION_JSON);
        context.getResp()
            .getOutputStream().print(context.getIdToken().toString());
        return AuthStatus.SEND_SUCCESS;
    }
}
