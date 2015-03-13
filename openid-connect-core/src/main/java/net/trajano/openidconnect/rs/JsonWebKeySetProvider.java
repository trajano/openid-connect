package net.trajano.openidconnect.rs;

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

import net.trajano.openidconnect.crypto.EcWebKey;
import net.trajano.openidconnect.crypto.JsonWebKey;
import net.trajano.openidconnect.crypto.JsonWebKeySet;
import net.trajano.openidconnect.crypto.KeyType;
import net.trajano.openidconnect.crypto.KeyUse;
import net.trajano.openidconnect.crypto.OctWebKey;
import net.trajano.openidconnect.crypto.RsaWebKey;

// TODO should we have the reader in jaspic and the writer in the rest api?
@Provider
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class JsonWebKeySetProvider implements MessageBodyReader<JsonWebKeySet>, MessageBodyWriter<JsonWebKeySet> {
@Context
Providers providers;
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
System.out.println("READ " + providers);
        final JsonArray keysArray = Json.createReader(inputStream)
                .readObject()
                .getJsonArray("keys");

        final JsonWebKeySet keySet = new JsonWebKeySet();
        for (final JsonValue key : keysArray) {
            final JsonObject keyObject = (JsonObject) key;
            final String kid = keyObject.containsKey("kid") ? keyObject.getString("kid") : null;
            final KeyType kty = KeyType.valueOf(keyObject.getString("kty"));
            final String alg = keyObject.containsKey("alg") ? keyObject.getString("alg") : null;
            final KeyUse use = KeyUse.valueOf(keyObject.getString("use"));
            if (kty == KeyType.RSA) {
                final RsaWebKey rsaWebKey = new RsaWebKey();
                rsaWebKey.setKty(kty);
                rsaWebKey.setKid(kid);
                rsaWebKey.setAlg(alg);
                rsaWebKey.setUse(use);
                if (use == KeyUse.enc) {
                    rsaWebKey.setD(keyObject.getString("d"));
                    rsaWebKey.setP(keyObject.getString("p"));
                }
                rsaWebKey.setN(keyObject.getString("n"));
                rsaWebKey.setE(keyObject.getString("e"));
                keySet.add(rsaWebKey);
            } else if (kty == KeyType.EC) {
                final EcWebKey ecWebKey = new EcWebKey();
                ecWebKey.setKty(kty);
                ecWebKey.setKid(kid);
                ecWebKey.setAlg(alg);
                ecWebKey.setUse(use);

                keySet.add(ecWebKey);
                // keyMap.put(kid, buildEcKey(keyObject));
            } else if (kty == KeyType.oct) {
                final OctWebKey octWebKey = new OctWebKey();
                octWebKey.setKty(kty);
                octWebKey.setKid(kid);
                octWebKey.setAlg(alg);
                octWebKey.setUse(use);
                keySet.add(octWebKey);

            } else {
                throw new IOException("kty of " + kty + " is not supported");
            }
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
