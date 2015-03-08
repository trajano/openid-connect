package net.trajano.openidconnect.internal;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.net.URI;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.json.Json;
import javax.json.JsonNumber;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonString;
import javax.json.JsonValue;
import javax.json.JsonValue.ValueType;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlTransient;

public class Util {

    @SafeVarargs
    public static <T> T firstNonNull(T... vals) {

        for (T val : vals) {
            if (val != null) {
                return val;
            }
        }
        return null;
    }

    public static JsonObject convertToJson(final Object obj) {

        final JsonObjectBuilder b = Json.createObjectBuilder();

        try {
            final Class<?> objClass = obj.getClass();
            for (final Field field : objClass.getDeclaredFields()) {
                String name = field.getName();
                if (field.getAnnotation(XmlTransient.class) != null) {
                    continue;
                }

                final XmlElement xmlElement = field.getAnnotation(XmlElement.class);
                if (xmlElement != null && xmlElement.name() != null) {
                    name = xmlElement.name();
                }
                field.setAccessible(true);
                final Object value = field.get(obj);
                if (value == null) {
                    continue;
                }
                if (field.getType()
                        .isEnum()) {
                    final String enumValue = ((Enum<?>) value).name();
                    final XmlEnumValue xmlEnumValue = ((Enum<?>) value).getDeclaringClass()
                            .getField(enumValue)
                            .getAnnotation(XmlEnumValue.class);
                    if (xmlEnumValue != null && xmlEnumValue.value() != null) {
                        b.add(name, xmlEnumValue.value());
                    } else {
                        b.add(name, enumValue);
                    }

                } else if (field.getType() == String.class) {
                    b.add(name, (String) value);
                } else if (field.getType() == Integer.class) {
                    b.add(name, (Integer) value);
                } else if (field.getType() == BigInteger.class) {
                    b.add(name, (BigInteger) value);
                }
            }
            return b.build();
        } catch (IllegalAccessException | SecurityException | NoSuchFieldException e1) {
            throw new RuntimeException(e1);
        }
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
    public static final String getParameter(final HttpServletRequest req,
            final String param) {

        final String parameter = req.getParameter(param);
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
    public static <E extends Enum<E>> E getParameter(final HttpServletRequest req,
            final String param,
            final Class<E> enumClass) {

        final String enumParam = getParameter(req, param);
        if (enumParam != null) {
            return valueOf(enumClass, enumParam);
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
    public static <E extends Enum<E>> Set<E> getParameterSet(final HttpServletRequest req,
            final String param,
            final Class<E> enumClass) {

        final Set<E> ret = new HashSet<>();
        final String enumParams = getParameter(req, param);
        if (enumParams != null) {
            for (final String enumParam : enumParams.split("\\s+")) {
                ret.add(Enum.valueOf(enumClass, enumParam));
            }
        }
        return Collections.unmodifiableSet(ret);
    }

    public static final boolean isNotNullOrEmpty(final String s) {

        return s != null && !s.trim()
                .isEmpty();
    }

    public static String join(final Iterable<String> values) {

        final StringBuilder b = new StringBuilder();
        for (final String value : values) {
            b.append(value);
            b.append(' ');
        }
        if (b.length() > 0) {
            b.delete(b.length() - 1, b.length());
        }
        return b.toString();

    }

    /**
     * Populates an object with the JSON data. Assumes a flat data structure,
     * does not support nested data structures.
     *
     * @param obj
     * @param json
     */
    public static <T> void populateWithJson(final T obj,
            final JsonObject json) {

        final Collection<Class<?>> SUPPORTED_CLASSES = Arrays.<Class<?>> asList(Enum.class, String.class, Integer.class, URI.class, Boolean.class, BigInteger.class, Long.class);
        final Class<?> objClass = obj.getClass();
        final Map<String, Field> fieldMap = new HashMap<>();
        for (final Field field : objClass.getDeclaredFields()) {
            if (!field.getType()
                    .isEnum() && !SUPPORTED_CLASSES.contains(field.getType())) {
                continue;
            }
            final XmlElement xmlElement = field.getAnnotation(XmlElement.class);
            if (xmlElement != null && xmlElement.name() != null) {
                fieldMap.put(xmlElement.name(), field);
            } else {
                fieldMap.put(field.getName(), field);
            }
        }
        try {
            for (final Entry<String, JsonValue> entry : json.entrySet()) {
                if (entry.getValue()
                        .getValueType() == ValueType.OBJECT) {
                    continue;
                } else if (entry.getValue()
                        .getValueType() == ValueType.NULL) {
                    continue;
                }
                final Field field = fieldMap.get(entry.getKey());
                if (field != null) {
                    field.setAccessible(true);
                    if (field.getType() == URI.class) {
                        field.set(obj, URI.create(((JsonString) entry.getValue()).getString()));
                    } else if (field.getType() == Boolean.class && entry.getValue()
                            .getValueType() == ValueType.TRUE) {
                        field.set(obj, true);
                    } else if (field.getType() == Boolean.class && entry.getValue()
                            .getValueType() == ValueType.FALSE) {
                        field.set(obj, false);
                    } else if (field.getType() == String.class) {
                        field.set(obj, ((JsonString) entry.getValue()).getString());
                    } else if (field.getType() == Integer.class) {
                        field.set(obj, ((JsonNumber) entry.getValue()).intValueExact());
                    } else if (field.getType() == BigInteger.class) {
                        field.set(obj, ((JsonNumber) entry.getValue()).bigIntegerValueExact());
                    } else if (field.getType() == Long.class) {
                        field.set(obj, ((JsonNumber) entry.getValue()).longValueExact());
                    } else if (field.getType()
                            .isEnum()) {
                        field.set(obj, valueOf((Class<? extends Enum>) field.getType(), ((JsonString) entry.getValue()).getString()));
                    }
                }
            }
        } catch (final IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    public static <E extends Enum<E>> String toString(final E value) {

        final Class<E> enumType = value.getDeclaringClass();
        try {
            final XmlEnumValue xmlEnumValue = enumType.getField(value.name())
                    .getAnnotation(XmlEnumValue.class);
            if (xmlEnumValue != null && xmlEnumValue.value() != null) {
                return xmlEnumValue.value();
            } else {
                return value.name();
            }
        } catch (NoSuchFieldException | SecurityException e1) {
            throw new RuntimeException(e1);
        }

    }

    public static <E extends Enum<E>> String toString(final Iterable<E> values) {

        final List<String> stringValues = new LinkedList<>();
        for (final E value : values) {
            stringValues.add(toString(value));
        }
        return join(stringValues);
    }

    public static List<String> splitToList(String in) {

        return Arrays.asList(in.split("\\s+"));
    }

    public static Set<String> splitToSet(String in) {

        return new HashSet<>(splitToList(in));
    }

    public static String toLocaleString(final Iterable<Locale> locales) {

        final List<String> stringValues = new LinkedList<>();
        for (final Locale locale : locales) {
            stringValues.add(locale.toLanguageTag());
        }
        return join(stringValues);
    }

    public static <E extends Enum<E>> E valueOf(final Class<E> enumType,
            final String name) {

        try {
            for (final E e : enumType.getEnumConstants()) {
                String ename = e.name();
                final XmlEnumValue xmlEnumValue = enumType.getField(ename)
                        .getAnnotation(XmlEnumValue.class);
                if (xmlEnumValue != null && xmlEnumValue.value() != null) {
                    ename = xmlEnumValue.value();
                }
                if (name.equals(ename)) {
                    return e;
                }
            }
        } catch (NoSuchFieldException | SecurityException e1) {
            throw new RuntimeException(e1);
        }
        throw new IllegalArgumentException("unable to find the value " + name + " in enum " + enumType);

    }

    public static <E extends Enum<E>> Set<E> splitToSet(Class<E> enumType,
            final String names) {

        Set<E> ret = new HashSet<>();
        for (String name : splitToList(names)) {
            ret.add(valueOf(enumType, name));
        }
        return ret;
    }

    public static <E extends Enum<E>> List<E> splitToList(Class<E> enumType,
            final String names) {

        List<E> ret = new LinkedList<>();
        for (String name : splitToList(names)) {
            ret.add(valueOf(enumType, name));
        }
        return ret;
    }

    public static List<Locale> splitToLocaleList(final String locales) {

        List<Locale> ret = new LinkedList<>();
        for (String languageTag : splitToList(locales)) {
            ret.add(Locale.forLanguageTag(languageTag));
        }
        return ret;
    }
}
