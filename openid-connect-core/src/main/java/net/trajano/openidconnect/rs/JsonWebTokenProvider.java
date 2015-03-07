package net.trajano.openidconnect.rs;

import static net.trajano.openidconnect.auth.JwtMediaType.APPLICATION_JWT;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;

import javax.ws.rs.Consumes;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.MessageBodyReader;
import javax.ws.rs.ext.MessageBodyWriter;
import javax.ws.rs.ext.Provider;

import net.trajano.openidconnect.crypto.JsonWebToken;

// TODO should we have the reader in jaspic and the writer in the rest api?
@Provider
@Produces(APPLICATION_JWT)
@Consumes(APPLICATION_JWT)
public class JsonWebTokenProvider implements MessageBodyReader<JsonWebToken>, MessageBodyWriter<JsonWebToken> {

    @Override
    public long getSize(final JsonWebToken jwks,
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

        return JsonWebToken.class.isAssignableFrom(type) && APPLICATION_JWT.equals(mediaType);
    }

    @Override
    public boolean isWriteable(final Class<?> type,
            final Type genericType,
            final Annotation[] annotations,
            final MediaType mediaType) {

        return isReadable(type, genericType, annotations, mediaType);
    }

    @Override
    public void writeTo(JsonWebToken jwt,
            Class<?> type,
            Type genericType,
            Annotation[] annotations,
            MediaType mediaType,
            MultivaluedMap<String, Object> arg5,
            OutputStream outputStream) throws IOException,
            WebApplicationException {

        new PrintStream(outputStream).print(jwt.toString());

    }

    @Override
    public JsonWebToken readFrom(Class<JsonWebToken> type,
            Type genericType,
            Annotation[] annotations,
            MediaType mediaType,
            MultivaluedMap<String, String> arg4,
            InputStream inputStream) throws IOException,
            WebApplicationException {

        
        // TODO Auto-generated method stub
        return null;
    }

}
