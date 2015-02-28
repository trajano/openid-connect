package net.trajano.openidconnect.core;

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

@Provider
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class IdTokenProvider implements MessageBodyReader<IdToken>, MessageBodyWriter<IdToken> {

    @Override
    public long getSize(final IdToken arg0,
            final Class<?> arg1,
            final Type arg2,
            final Annotation[] arg3,
            final MediaType arg4) {

        return -1;
    }

    @Override
    public boolean isReadable(final Class<?> type,
            final Type genericType,
            final Annotation[] arg2,
            final MediaType mediaType) {

        return type == IdToken.class && mediaType == MediaType.APPLICATION_JSON_TYPE;
    }

    @Override
    public boolean isWriteable(final Class<?> type,
            final Type genericType,
            final Annotation[] arg2,
            final MediaType mediaType) {

        return type == IdToken.class && mediaType == MediaType.APPLICATION_JSON_TYPE;
    }

    @Override
    public IdToken readFrom(final Class<IdToken> type,
            final Type genericType,
            final Annotation[] arg2,
            final MediaType mediaType,
            final MultivaluedMap<String, String> arg4,
            final InputStream is) throws IOException,
            WebApplicationException {

        final JsonObject obj = Json.createReader(is)
                .readObject();
        final IdToken idToken = new IdToken();
        idToken.setAcr(obj.getString("acr"));
        idToken.setAmr(obj.getString("amr"));
        idToken.setAud(obj.getString("aud"));
        idToken.setAuthTime(obj.getInt("auth_time"));
        idToken.setAzp(obj.getString("azp"));
        idToken.setExp(obj.getInt("exp"));
        idToken.setIat(obj.getInt("oat"));
        idToken.setIss(obj.getString("iss"));
        idToken.setNonce(obj.getString("nonce"));
        idToken.setSub(obj.getString("sub"));
        return idToken;
    }

    @Override
    public void writeTo(final IdToken idToken,
            final Class<?> type,
            final Type genericType,
            final Annotation[] arg3,
            final MediaType mediaType,
            final MultivaluedMap<String, Object> arg5,
            final OutputStream os) throws IOException,
            WebApplicationException {

        final JsonObjectBuilder b = Json.createObjectBuilder();
        b.add("acr", idToken.getAcr());
        b.add("amr", idToken.getAmr());
        b.add("aud", idToken.getAud());
        b.add("auth_time", idToken.getAuthTime());
        b.add("azp", idToken.getAzp());
        b.add("iat", idToken.getIat());
        b.add("iss", idToken.getIss());
        b.add("nonce", idToken.getNonce());
        b.add("sub", idToken.getSub());

        final JsonWriter w = Json.createWriter(os);
        w.writeObject(b.build());
        w.close();

    }

}
