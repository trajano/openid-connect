package net.trajano.openidconnect.jaspic.internal;

import java.text.MessageFormat;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Preconfigured logger.
 *
 * @author Archimedes
 */
public class Log {

    private static final Logger LOG;

    /**
     * Messages resource path.
     */
    private static final String MESSAGES = "META-INF/JaspicMessages";

    private static final ResourceBundle R = ResourceBundle.getBundle(MESSAGES);

    static {
        LOG = Logger.getLogger("net.trajano.oidc.jaspic", MESSAGES);
    }

    public static void fine(final String key,
            final Object... params) {

        LOG.log(Level.FINE, key, params);
    }

    public static Logger getInstance() {

        return LOG;
    }

    public static boolean isFinestLoggable() {

        return LOG.isLoggable(Level.FINEST);
    }

    public static String r(final String key,
            Object... params) {

        if (params.length == 0)

            return R.getString(key);
        else
            return MessageFormat.format(R.getString(key), params);
    }

    public static void severe(final String key,
            final Object... params) {

        LOG.log(Level.SEVERE, key, params);
    }

}
