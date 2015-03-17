package net.trajano.openidconnect.jaspic.internal;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.security.auth.message.AuthStatus;

import net.trajano.openidconnect.jaspic.internal.processors.IdTokenRequestProcessor;
import net.trajano.openidconnect.jaspic.internal.processors.LogoutGotoRequestProcessor;
import net.trajano.openidconnect.jaspic.internal.processors.LogoutRequestProcessor;
import net.trajano.openidconnect.jaspic.internal.processors.PostLogoutRequestProcessor;
import net.trajano.openidconnect.jaspic.internal.processors.SecurityAssertionFailureRequestProcessor;
import net.trajano.openidconnect.jaspic.internal.processors.SecurityAssertionPassedRequestProcessor;
import net.trajano.openidconnect.jaspic.internal.processors.UserInfoRequestProcessor;

public class ValidateRequestProcessors implements ValidateRequestProcessor {

    private static final ValidateRequestProcessors INSTANCE;

    static {
        INSTANCE = new ValidateRequestProcessors();
    }

    public static ValidateRequestProcessor getInstance() {

        return INSTANCE;
    }

    private final ValidateRequestProcessor[] processors = {

    new IdTokenRequestProcessor(),

    new UserInfoRequestProcessor(),

    new LogoutRequestProcessor(),

    new LogoutGotoRequestProcessor(),

    new SecurityAssertionFailureRequestProcessor(),

    new PostLogoutRequestProcessor(),

    new SecurityAssertionPassedRequestProcessor() };

    @Override
    public boolean canValidateRequest(final ValidateContext context) {

        for (final ValidateRequestProcessor processor : processors) {
            if (processor.canValidateRequest(context)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public AuthStatus validateRequest(final ValidateContext context) throws IOException,
            GeneralSecurityException {

        for (final ValidateRequestProcessor processor : processors) {
            if (processor.canValidateRequest(context)) {
                return processor.validateRequest(context);
            }
        }
        return null;
    }
}
