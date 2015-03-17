package net.trajano.openidconnect.jaspic.internal.processors;

import java.io.IOException;
import java.net.HttpURLConnection;

import javax.security.auth.message.AuthStatus;

import net.trajano.openidconnect.jaspic.OpenIdConnectAuthModule;
import net.trajano.openidconnect.jaspic.internal.Log;
import net.trajano.openidconnect.jaspic.internal.ValidateContext;
import net.trajano.openidconnect.jaspic.internal.ValidateRequestProcessor;

/**
 * Processes any requests that would fail the security assertions.
 * 
 * @author Archimedes
 */
public class SecurityAssertionFailureRequestProcessor implements ValidateRequestProcessor {

    @Override
    public boolean canValidateRequest(final ValidateContext context) {

        return (!context.isSecure() && (context.isMandatory() || context.isRequestUri((OpenIdConnectAuthModule.REDIRECTION_ENDPOINT_URI_KEY)) || context.isRequestUri("logout_redirection_endpoint")));
    }

    @Override
    public AuthStatus validateRequest(final ValidateContext context) throws IOException {

        context.getResp()
                .sendError(HttpURLConnection.HTTP_FORBIDDEN, Log.r("SSLReq"));
        return AuthStatus.SEND_FAILURE;
    }
}
