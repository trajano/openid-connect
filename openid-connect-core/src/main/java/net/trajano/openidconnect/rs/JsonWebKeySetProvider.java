package net.trajano.openidconnect.rs;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
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

    @Context
    public void setProviders(Providers providers) {

        this.providers = providers;
    }

    @Context
    private JsonWebKeyProvider p2;

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
        MessageBodyReader<JsonWebKey> reader = providers.getMessageBodyReader(JsonWebKey.class, null, annotations, mediaType);

        for (final JsonValue key : keysArray) {
            InputStream keyStream = new ByteArrayInputStream(key.toString()
                    .getBytes(CharSets.UTF8));
            JsonWebKey jsonWebKey = reader.readFrom(JsonWebKey.class, null, annotations, mediaType, null, keyStream);
            keySet.add(jsonWebKey);
        }

        return keySet;
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

        System.out.println("WRITE " + providers);
        JsonArrayBuilder keysArray = Json.createArrayBuilder();
        for (JsonWebKey key : jwks.getKeys()) {
            JsonObjectBuilder keyBuilder = Json.createObjectBuilder();
            key.buildJsonObject(keyBuilder);
            keysArray.add(keyBuilder);
        }
        JsonObject jwksObject = Json.createObjectBuilder()
                .add("keys", keysArray)
                .build();
        JsonWriter jsonWriter = Json.createWriter(os);
        jsonWriter.write(jwksObject);
    }
}
