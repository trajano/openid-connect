package net.trajano.openidconnect.jaspic.internal.processors;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.security.auth.message.AuthStatus;
import javax.ws.rs.core.MediaType;

import net.trajano.openidconnect.jaspic.OpenIdConnectAuthModule;
import net.trajano.openidconnect.jaspic.internal.ValidateContext;
import net.trajano.openidconnect.jaspic.internal.ValidateRequestProcessor;

public class UserInfoRequestProcessor implements
    ValidateRequestProcessor {

    @Override
    public boolean canValidateRequest(final ValidateContext context) {

        if (!context.hasTokenCookie()) {
            return false;
        }

        return context.isSecure() && context.isGetRequest() && context.isRequestUri(OpenIdConnectAuthModule.USERINFO_URI_KEY);
    }

    /**
     * {@inheritDoc}. Although this really should return AuthStatus.SEND_SUCCESS
     * based on the spec, to make it work with WebSphere Liberty it returns
     * {@link AuthStatus#SEND_CONTINUE}.
     *
     * @return {@link AuthStatus#SEND_CONTINUE}
     */
    @Override
    public AuthStatus validateRequest(final ValidateContext context) throws IOException,
        GeneralSecurityException {

        context.setContentType(MediaType.APPLICATION_JSON);
        context.getResp()
            .getWriter()
            .print(context.getTokenCookie()
                .getUserInfo());
        return AuthStatus.SEND_CONTINUE;
    }

}
