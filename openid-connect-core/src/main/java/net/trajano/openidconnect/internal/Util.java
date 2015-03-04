package net.trajano.openidconnect.internal;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

public class Util {

    public static final boolean isNotNullOrEmpty(String s) {

        return s != null && !s.trim()
                .isEmpty();
    }

    /**
     * Checks if the parameter being passed in is not null or empty. If it is
     * not null or empty it will return the value of the paramter otherwise it
     * will return null. This will not return an empty string.
     * 
     * @param req
     * @param param
     * @return
     */
    public static final String getParameter(HttpServletRequest req,
            String param) {

        String parameter = req.getParameter(param);
        if (Util.isNotNullOrEmpty(parameter)) {
            return parameter;
        } else {
            return null;
        }
    }

    /**
     * Returns a valid parameter value and will convert the value to the enum.
     * 
     * @param req
     * @param param
     * @param enumClass
     */
    public static <E extends Enum<E>> E getParameter(HttpServletRequest req,
            String param,
            Class<E> enumClass) {

        String enumParam = getParameter(req, param);
        if (enumParam != null) {
            return Enum.valueOf(enumClass, enumParam);
        }
        return null;
    }

    /**
     * Returns a set for the enums or an empty set if nothing was defined.
     * 
     * @param req
     * @param param
     * @param enumClass
     */
    public static <E extends Enum<E>> Set<E> getParameterSet(HttpServletRequest req,
            String param,
            Class<E> enumClass) {

        Set<E> ret = new HashSet<>();
        String enumParams = getParameter(req, param);
        if (enumParams != null) {
            for (String enumParam : enumParams.split("\\s+")) {
                ret.add(Enum.valueOf(enumClass, enumParam));
            }
        }
        return Collections.unmodifiableSet(ret);
    }
}
