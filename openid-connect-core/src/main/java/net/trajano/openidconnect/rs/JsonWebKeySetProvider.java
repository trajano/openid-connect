package net.trajano.openidconnect.rs;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonValue;
import javax.json.JsonWriter;
import javax.ws.rs.Consumes;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.MessageBodyReader;
import javax.ws.rs.ext.MessageBodyWriter;
import javax.ws.rs.ext.Provider;
import javax.ws.rs.ext.Providers;

import net.trajano.openidconnect.crypto.JsonWebKey;
import net.trajano.openidconnect.crypto.JsonWebKeySet;
import net.trajano.openidconnect.internal.CharSets;

// TODO should we have the reader in jaspic and the writer in the rest api?
@Provider
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class JsonWebKeySetProvider implements MessageBodyReader<JsonWebKeySet>, MessageBodyWriter<JsonWebKeySet> {

    private Providers providers;

    @Override
    public long getSize(final JsonWebKeySet jwks,
            final Class<?> type,
            final Type genericType,
            final Annotation[] annotations,
            final MediaType mediaType) {

        return -1;
    }

    @Override
    public boolean isReadable(final Class<?> type,
            final Type genericType,
            final Annotation[] annotations,
            final MediaType mediaType) {

        return JsonWebKeySet.class.isAssignableFrom(type) && MediaType.APPLICATION_JSON_TYPE.isCompatible(mediaType);
    }

    @Override
    public boolean isWriteable(final Class<?> type,
            final Type genericType,
            final Annotation[] annotations,
            final MediaType mediaType) {

        return isReadable(type, genericType, annotations, mediaType);
    }

    @Override
    public JsonWebKeySet readFrom(final Class<JsonWebKeySet> type,
            final Type genericType,
            final Annotation[] annotations,
            final MediaType mediaType,
            final MultivaluedMap<String, String> httpHeaders,
            final InputStream inputStream) throws IOException,
            WebApplicationException {

        final JsonArray keysArray = Json.createReader(inputStream)
                .readObject()
                .getJsonArray("keys");

        final JsonWebKeySet keySet = new JsonWebKeySet();
        final MessageBodyReader<JsonWebKey> reader = providers.getMessageBodyReader(JsonWebKey.class, JsonWebKey.class, annotations, mediaType);
        System.out.println(reader.getClass());
        for (final JsonValue key : keysArray) {
            final InputStream keyStream = new ByteArrayInputStream(key.toString()
                    .getBytes(CharSets.UTF8));
            final JsonWebKey jsonWebKey = reader.readFrom(JsonWebKey.class, null, annotations, mediaType, null, keyStream);
            keySet.add(jsonWebKey);
        }

        return keySet;
    }

    @Context
    public void setProviders(final Providers providers) {

        this.providers = providers;
    }

    @Override
    public void writeTo(final JsonWebKeySet jwks,
            final Class<?> type,
            final Type genericType,
            final Annotation[] annotations,
            final MediaType mediaType,
            final MultivaluedMap<String, Object> httpHeaders,
            final OutputStream os) throws IOException,
            WebApplicationException {

        final MessageBodyWriter<JsonWebKey> writer = providers.getMessageBodyWriter(JsonWebKey.class, JsonWebKey.class, annotations, mediaType);
        final JsonArrayBuilder keysArray = Json.createArrayBuilder();
        for (final JsonWebKey key : jwks.getKeys()) {
            final ByteArrayOutputStream keyStream = new ByteArrayOutputStream();
            writer.writeTo(key, JsonWebKey.class, null, annotations, mediaType, null, keyStream);
            keyStream.close();
            keysArray.add(Json.createReader(new ByteArrayInputStream(keyStream.toByteArray()))
                    .readObject());
        }
        final JsonObject jwksObject = Json.createObjectBuilder()
                .add("keys", keysArray)
                .build();
        final JsonWriter w = Json.createWriter(os);
        w.write(jwksObject);
        w.close();
    }
}
