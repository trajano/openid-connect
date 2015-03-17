package net.trajano.openidconnect.jaspic.internal.processors;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.security.auth.message.AuthStatus;

import net.trajano.openidconnect.jaspic.OpenIdConnectAuthModule;
import net.trajano.openidconnect.jaspic.internal.ValidateContext;
import net.trajano.openidconnect.jaspic.internal.ValidateRequestProcessor;

public class LogoutGotoRequestProcessor implements ValidateRequestProcessor {

    /**
     * This only supports the scenario when logout goto uri is not available.
     */
    @Override
    public boolean canValidateRequest(final ValidateContext context) {

        if (!context.hasOption(OpenIdConnectAuthModule.LOGOUT_GOTO_URI_KEY)) {
            return false;
        }

        return context.isSecure() && context.isGetRequest() && context.isRequestUri(OpenIdConnectAuthModule.LOGOUT_URI_KEY);
    }

    @Override
    public AuthStatus validateRequest(final ValidateContext context) throws IOException,
            GeneralSecurityException {

        context.getResp()
                .sendRedirect(context.getOption(OpenIdConnectAuthModule.LOGOUT_GOTO_URI_KEY));
        return AuthStatus.SEND_SUCCESS;
    }

}
