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
import javax.json.JsonString;
import javax.json.JsonValue;
import javax.json.JsonWriter;
import javax.ws.rs.Consumes;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.MessageBodyReader;
import javax.ws.rs.ext.MessageBodyWriter;
import javax.ws.rs.ext.Provider;

import net.trajano.openidconnect.token.IdToken;

@Provider
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class IdTokenProvider implements MessageBodyReader<IdToken>, MessageBodyWriter<IdToken> {

    @Override
    public long getSize(final IdToken token,
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

        return type == IdToken.class && MediaType.APPLICATION_JSON_TYPE.equals(mediaType);
    }

    @Override
    public boolean isWriteable(final Class<?> type,
            final Type genericType,
            final Annotation[] arg2,
            final MediaType mediaType) {

        return isReadable(type, genericType, arg2, mediaType);
    }

    @Override
    public IdToken readFrom(final Class<IdToken> type,
            final Type genericType,
            final Annotation[] arg2,
            final MediaType mediaType,
            final MultivaluedMap<String, String> arg4,
            final InputStream is) throws IOException {

        final JsonObject obj = Json.createReader(is)
                .readObject();
        final IdToken idToken = new IdToken();
        if (obj.containsKey("acr")) {
            idToken.setAcr(obj.getString("acr"));
        }
        if (obj.containsKey("amr")) {
            final JsonArray amrs = obj.getJsonArray("amr");
            final String[] amrArray = new String[amrs.size()];
            int i = 0;
            for (final JsonValue amr : amrs) {
                amrArray[i] = ((JsonString) amr).getString();
                ++i;
            }
            idToken.setAmr(amrArray);
        }

        idToken.setAud(obj.getString("aud"));
        if (obj.containsKey("auth_time")) {
            idToken.setAuthTime(obj.getInt("auth_time"));
        }
        if (obj.containsKey("azp")) {
            idToken.setAzp(obj.getString("azp"));
        }

        idToken.setExp(obj.getInt("exp"));
        idToken.setIat(obj.getInt("iat"));
        idToken.setIss(obj.getString("iss"));
        if (obj.containsKey("nonce")) {
            idToken.setNonce(obj.getString("nonce"));
        }
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
            final OutputStream os) throws IOException {

        final JsonObjectBuilder b = Json.createObjectBuilder();
        if (idToken.getAcr() != null) {
            b.add("acr", idToken.getAcr());
        }
        if (idToken.getAmr() != null) {
            final JsonArrayBuilder amrBuilder = Json.createArrayBuilder();
            for (final String amr : idToken.getAmr()) {
                amrBuilder.add(amr);
            }
            b.add("amr", amrBuilder);
        }

        b.add("aud", idToken.getAud());
        if (idToken.getAuthTime() != 0) {
            b.add("auth_time", idToken.getAuthTime());
        }
        if (idToken.getAzp() != null) {
            b.add("azp", idToken.getAzp());
        }
        if (idToken.getAtHash() != null) {
            b.add("at_hash", idToken.getAtHash());
        }
        if (idToken.getCHash() != null) {
            b.add("c_hash", idToken.getCHash());
        }
        b.add("iat", idToken.getIat());
        b.add("exp", idToken.getExp());
        b.add("iss", idToken.getIss());
        if (idToken.getNonce() != null) {
            b.add("nonce", idToken.getNonce());
        }
        b.add("sub", idToken.getSub());

        final JsonWriter w = Json.createWriter(os);
        w.writeObject(b.build());
        w.close();

    }

}
