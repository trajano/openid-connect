package net.trajano.openidconnect.jaspic.internal.processors;

import static net.trajano.openidconnect.core.OpenIdConnectKey.STATE;
import static net.trajano.openidconnect.jaspic.internal.Utils.isNullOrEmpty;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.module.ServerAuthModule;

import net.trajano.openidconnect.jaspic.internal.ValidateContext;
import net.trajano.openidconnect.jaspic.internal.ValidateRequestProcessor;

public class PostLogoutCallbackRequestProcessor implements ValidateRequestProcessor {

    /**
     * Checks to see whether post logout redirection end point callback the
     * {@link ServerAuthModule} is called by the user agent. This is indicated
     * by the presence of a <code>state</code> on the URL. The user agent would
     * be a web browser that got a redirect or automatic form post sent by the
     * OP.
     *
     * @param req
     *            HTTP servlet request
     * @return the module is called by the resource owner.
     */
    @Override
    public boolean canValidateRequest(final ValidateContext context) {

        return context.isSecure() && context.isRequestUri("logout_redirection_endpoint") && !isNullOrEmpty(context.getReq()
                .getParameter(STATE));
    }

    @Override
    public AuthStatus validateRequest(final ValidateContext context) throws IOException,
            GeneralSecurityException {

        context.redirectToState();
        return AuthStatus.SEND_SUCCESS;
    }

}
