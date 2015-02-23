package net.trajano.openidconnect.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonValue;
import javax.ws.rs.Consumes;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.MessageBodyReader;
import javax.ws.rs.ext.MessageBodyWriter;
import javax.ws.rs.ext.Provider;

@Provider
@Consumes(MediaType.APPLICATION_JSON)
public class JsonWebKeySetProvider implements MessageBodyReader<JsonWebKeySet>, MessageBodyWriter<JsonWebKeySet> {

    @Override
    public long getSize(final JsonWebKeySet jwks,
            final Class<?> arg1,
            final Type arg2,
            final Annotation[] arg3,
            final MediaType arg4) {

        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public boolean isReadable(final Class<?> type,
            final Type genericType,
            final Annotation[] annotations,
            final MediaType mediaType) {

        return type == JsonWebKeySet.class && mediaType == MediaType.APPLICATION_JSON_TYPE;
    }

    @Override
    public boolean isWriteable(final Class<?> arg0,
            final Type arg1,
            final Annotation[] arg2,
            final MediaType arg3) {

        // TODO Auto-generated method stub
        return false;
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
        for (final JsonValue key : keysArray) {
            final JsonObject keyObject = (JsonObject) key;
            final String kid = keyObject.getString("kid");
            final KeyType kty = KeyType.valueOf(keyObject.getString("kty"));
            final JsonWebAlgorithm alg = JsonWebAlgorithm.valueOf(keyObject.getString("alg"));
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

                // keyMap.put(kid, buildEcKey(keyObject));
            } else if (kty == KeyType.oct) {
                final OctWebKey octWebKey = new OctWebKey();
                octWebKey.setKty(kty);
                octWebKey.setKid(kid);
                octWebKey.setAlg(alg);
                octWebKey.setUse(use);

            } else {
                throw new IOException("kty of " + kty + " is not supported");
            }
        }

        return keySet;
    }

    @Override
    public void writeTo(final JsonWebKeySet arg0,
            final Class<?> arg1,
            final Type arg2,
            final Annotation[] arg3,
            final MediaType arg4,
            final MultivaluedMap<String, Object> arg5,
            final OutputStream arg6) throws IOException,
            WebApplicationException {

        // TODO Auto-generated method stub

    }
}
