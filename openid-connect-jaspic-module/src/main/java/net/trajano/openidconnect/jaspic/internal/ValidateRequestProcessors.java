package net.trajano.openidconnect.jaspic.internal;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.LinkedList;
import java.util.List;

import javax.security.auth.message.AuthStatus;

import net.trajano.openidconnect.jaspic.internal.processors.IdTokenRequestProcessor;
import net.trajano.openidconnect.jaspic.internal.processors.LogoutGotoRequestProcessor;
import net.trajano.openidconnect.jaspic.internal.processors.LogoutRequestProcessor;
import net.trajano.openidconnect.jaspic.internal.processors.UserInfoRequestProcessor;

public class ValidateRequestProcessors implements ValidateRequestProcessor {

    private static final ValidateRequestProcessors INSTANCE;

    static {
        INSTANCE = new ValidateRequestProcessors();
        INSTANCE.add(new IdTokenRequestProcessor());
        INSTANCE.add(new UserInfoRequestProcessor());
        INSTANCE.add(new LogoutRequestProcessor());
        INSTANCE.add(new LogoutGotoRequestProcessor());
    }

    public static ValidateRequestProcessor getInstance() {

        return INSTANCE;
    }

    private final List<ValidateRequestProcessor> processors = new LinkedList<>();

    private ValidateRequestProcessors add(final ValidateRequestProcessor processor) {

        processors.add(processor);
        return this;
    }

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
            System.out.println("trying " + processor);
            if (processor.canValidateRequest(context)) {
                return processor.validateRequest(context);
            }
        }
        return null;
    }
}
