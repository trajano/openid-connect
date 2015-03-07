package net.trajano.openidconnect.rs;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonWriter;
import javax.ws.rs.Consumes;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.MessageBodyReader;
import javax.ws.rs.ext.MessageBodyWriter;
import javax.ws.rs.ext.Provider;

import net.trajano.openidconnect.crypto.EcWebKey;
import net.trajano.openidconnect.crypto.JsonWebAlgorithm;
import net.trajano.openidconnect.crypto.JsonWebKey;
import net.trajano.openidconnect.crypto.KeyType;
import net.trajano.openidconnect.crypto.KeyUse;
import net.trajano.openidconnect.crypto.OctWebKey;
import net.trajano.openidconnect.crypto.RsaWebKey;

// TODO should we have the reader in jaspic and the writer in the rest api?
@Provider
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class JsonWebKeyProvider implements MessageBodyReader<JsonWebKey>, MessageBodyWriter<JsonWebKey> {

    @Override
    public long getSize(final JsonWebKey jwks,
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

        return JsonWebKey.class.isAssignableFrom(type) && MediaType.APPLICATION_JSON_TYPE.equals(mediaType);
    }

    @Override
    public boolean isWriteable(final Class<?> type,
            final Type genericType,
            final Annotation[] annotations,
            final MediaType mediaType) {

        return isReadable(type, genericType, annotations, mediaType);
    }

    @Override
    public JsonWebKey readFrom(final Class<JsonWebKey> type,
            final Type genericType,
            final Annotation[] annotations,
            final MediaType mediaType,
            final MultivaluedMap<String, String> httpHeaders,
            final InputStream inputStream) throws IOException,
            WebApplicationException {

        final JsonObject keyObject = Json.createReader(inputStream)
                .readObject();

        final String kid = keyObject.containsKey("kid") ? keyObject.getString("kid") : null;
        final KeyType kty = KeyType.valueOf(keyObject.getString("kty"));
        final JsonWebAlgorithm alg = keyObject.containsKey("alg") ? JsonWebAlgorithm.valueOf(keyObject.getString("alg")) : null;
        final KeyUse use = keyObject.containsKey("use") ? KeyUse.valueOf(keyObject.getString("use")) : null;
        if (kty == KeyType.RSA) {
            final RsaWebKey rsaWebKey = new RsaWebKey();
            rsaWebKey.setKty(kty);
            if (kid != null)
                rsaWebKey.setKid(kid);
            if (alg != null)
                rsaWebKey.setAlg(alg);
            if (use != null)
                rsaWebKey.setUse(use);
            if (use == KeyUse.enc || keyObject.containsKey("qi")) {
                rsaWebKey.setD(keyObject.getString("d"));
                rsaWebKey.setP(keyObject.getString("p"));
                rsaWebKey.setDp(keyObject.getString("dp"));
                rsaWebKey.setDq(keyObject.getString("dq"));
                rsaWebKey.setQ(keyObject.getString("q"));
                rsaWebKey.setQi(keyObject.getString("qi"));
            }
            rsaWebKey.setN(keyObject.getString("n"));
            rsaWebKey.setE(keyObject.getString("e"));
            return rsaWebKey;
        } else if (kty == KeyType.EC) {
            final EcWebKey ecWebKey = new EcWebKey();
            ecWebKey.setKty(kty);
            if (kid != null)
                ecWebKey.setKid(kid);
            if (alg != null)
                ecWebKey.setAlg(alg);
            if (use != null)
                ecWebKey.setUse(use);

            return ecWebKey;
        } else if (kty == KeyType.oct) {
            final OctWebKey octWebKey = new OctWebKey();
            octWebKey.setKty(kty);
            if (kid != null)
                octWebKey.setKid(kid);
            if (alg != null)
                octWebKey.setAlg(alg);
            if (use != null)
                octWebKey.setUse(use);
            return octWebKey;

        } else {
            throw new IOException("kty of " + kty + " is not supported");
        }
    }

    @Override
    public void writeTo(final JsonWebKey jwks,
            final Class<?> type,
            final Type genericType,
            final Annotation[] annotations,
            final MediaType mediaType,
            final MultivaluedMap<String, Object> httpHeaders,
            final OutputStream os) throws IOException,
            WebApplicationException {

        JsonObjectBuilder keyBuilder = Json.createObjectBuilder();
        jwks.buildJsonObject(keyBuilder);

        JsonWriter jsonWriter = Json.createWriter(os);
        jsonWriter.write(keyBuilder.build());
    }
}
