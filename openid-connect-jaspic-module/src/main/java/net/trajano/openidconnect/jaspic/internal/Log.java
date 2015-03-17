package net.trajano.openidconnect.jaspic.internal;

import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Preconfigured logger.
 *
 * @author Archimedes
 */
public class Log extends Logger {

    private static final Log LOG = new Log();

    /**
     * Messages resource path.
     */
    private static final String MESSAGES = "META-INF/Messages";

    private static final ResourceBundle R = ResourceBundle.getBundle(MESSAGES);

    public static Log getInstance() {

        return LOG;
    }

    public static String r(String key) {

        return R.getString(key);
    }

    private Log() {

        super("net.trajano.oidc.jaspic", MESSAGES);
    }

    public void fine(final String key,
            final Object... params) {

        log(Level.FINE, key, params);
    }

}
