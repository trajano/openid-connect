package net.trajano.openidconnect.rs;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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

import net.trajano.openidconnect.auth.AuthenticationRequest;
import net.trajano.openidconnect.crypto.JsonWebKeySet;

@Provider
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class AuthenticationRequestJsonProvider implements MessageBodyReader<AuthenticationRequest>, MessageBodyWriter<AuthenticationRequest> {

    @Override
    public long getSize(AuthenticationRequest arg0,
            Class<?> arg1,
            Type arg2,
            Annotation[] arg3,
            MediaType arg4) {

        return -1;
    }

    @Override
    public boolean isWriteable(Class<?> type,
            Type arg1,
            Annotation[] arg2,
            MediaType mediaType) {

        return JsonWebKeySet.class.isAssignableFrom(type) && MediaType.APPLICATION_JSON_TYPE.equals(mediaType);
    }

    @Override
    public void writeTo(AuthenticationRequest arg0,
            Class<?> arg1,
            Type arg2,
            Annotation[] arg3,
            MediaType arg4,
            MultivaluedMap<String, Object> arg5,
            OutputStream arg6) throws IOException,
            WebApplicationException {

        // TODO Auto-generated method stub

    }

    @Override
    public boolean isReadable(Class<?> type,
            Type arg1,
            Annotation[] arg2,
            MediaType mediaType) {

        return JsonWebKeySet.class.isAssignableFrom(type) && MediaType.APPLICATION_JSON_TYPE.equals(mediaType);
    }

    @Override
    public AuthenticationRequest readFrom(Class<AuthenticationRequest> arg0,
            Type arg1,
            Annotation[] arg2,
            MediaType arg3,
            MultivaluedMap<String, String> arg4,
            InputStream arg5) throws IOException,
            WebApplicationException {

        // TODO Auto-generated method stub
        return null;
    }

}
