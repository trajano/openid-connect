package net.trajano.openidconnect.internal;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.net.URI;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
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

    /**
     * Populates an object with the JSON data. Assumes a flat data structure,
     * does not support nested data structures.
     * 
     * @param obj
     * @param json
     */
    public static <T> void populateWithJson(T obj,
            JsonObject json) {

        Collection<Class<?>> SUPPORTED_CLASSES = Arrays.<Class<?>> asList(Enum.class, String.class, Integer.class, URI.class, Boolean.class, BigInteger.class, Long.class);
        Class<?> objClass = obj.getClass();
        Map<String, Field> fieldMap = new HashMap<>();
        for (Field field : objClass.getDeclaredFields()) {
            if (!field.getType()
                    .isEnum() && !SUPPORTED_CLASSES.contains(field.getType()))
                continue;
            XmlElement xmlElement = field.getAnnotation(XmlElement.class);
            if (xmlElement != null && xmlElement.name() != null)
                fieldMap.put(xmlElement.name(), field);
            else
                fieldMap.put(field.getName(), field);
        }
        try {
            for (Entry<String, JsonValue> entry : json.entrySet()) {
                if (entry.getValue()
                        .getValueType() == ValueType.OBJECT) {
                    continue;
                } else if (entry.getValue()
                        .getValueType() == ValueType.NULL) {
                    continue;
                }
                Field field = fieldMap.get(entry.getKey());
                if (field != null) {
                    field.setAccessible(true);
                    if (field.getType() == URI.class) {
                        field.set(obj, URI.create(((JsonString) (entry.getValue())).getString()));
                    } else if (field.getType() == Boolean.class && entry.getValue()
                            .getValueType() == ValueType.TRUE) {
                        field.set(obj, true);
                    } else if (field.getType() == Boolean.class && entry.getValue()
                            .getValueType() == ValueType.FALSE) {
                        field.set(obj, false);
                    } else if (field.getType() == String.class) {
                        field.set(obj, ((JsonString) (entry.getValue())).getString());
                    } else if (field.getType() == Integer.class) {
                        field.set(obj, ((JsonNumber) (entry.getValue())).intValueExact());
                    } else if (field.getType() == BigInteger.class) {
                        field.set(obj, ((JsonNumber) (entry.getValue())).bigIntegerValueExact());
                    } else if (field.getType() == Long.class) {
                        field.set(obj, ((JsonNumber) (entry.getValue())).longValueExact());
                    } else if (field.getType()
                            .isEnum()) {
                        field.set(obj, valueOf((Class) field.getType(), ((JsonString) (entry.getValue())).getString()));
                    }
                }
            }
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    public static <E extends Enum<E>> E valueOf(Class<E> enumType,
            String name) {

        try {
            for (E e : enumType.getEnumConstants()) {
                String ename = e.name();
                XmlEnumValue xmlEnumValue = enumType.getField(ename)
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

    public static JsonObject convertToJson(Object obj) {

        JsonObjectBuilder b = Json.createObjectBuilder();

        try {
            Class<?> objClass = obj.getClass();
            for (Field field : objClass.getDeclaredFields()) {
                String name = field.getName();
                if (field.getAnnotation(XmlTransient.class) != null) {
                    continue;
                }

                XmlElement xmlElement = field.getAnnotation(XmlElement.class);
                if (xmlElement != null && xmlElement.name() != null)
                    name = xmlElement.name();
                field.setAccessible(true);
                Object value = field.get(obj);
                if (value == null) {
                    continue;
                }
                if (field.getType()
                        .isEnum()) {
                    String enumValue = ((Enum<?>) value).name();
                    XmlEnumValue xmlEnumValue = ((Enum<?>) value).getDeclaringClass()
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
}
