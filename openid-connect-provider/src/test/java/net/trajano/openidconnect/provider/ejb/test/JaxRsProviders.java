package net.trajano.openidconnect.provider.ejb.test;

import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.ext.ContextResolver;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.MessageBodyReader;
import javax.ws.rs.ext.MessageBodyWriter;
import javax.ws.rs.ext.Providers;

public class JaxRsProviders implements Providers {

    private Set<MessageBodyReader<?>> messageBodyReaders = new HashSet<>();

    private Set<MessageBodyWriter<?>> messageBodyWriters = new HashSet<>();

    public JaxRsProviders add(final Object provider) {

        if (provider instanceof MessageBodyReader<?>) {
            messageBodyReaders.add((MessageBodyReader<?>) provider);
        }
        if (provider instanceof MessageBodyWriter<?>) {
            messageBodyWriters.add((MessageBodyWriter<?>) provider);
        }
        return this;
    }

    @Override
    public <T> ContextResolver<T> getContextResolver(final Class<T> arg0,
            final MediaType arg1) {

        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public <T extends Throwable> ExceptionMapper<T> getExceptionMapper(final Class<T> arg0) {

        // TODO Auto-generated method stub
        return null;
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T> MessageBodyReader<T> getMessageBodyReader(final Class<T> type,
            final Type genericType,
            final Annotation[] annotations,
            final MediaType mediaType) {

        for (final MessageBodyReader<?> provider : messageBodyReaders) {
            if (provider.isReadable(type, genericType, annotations, mediaType)) {
                return (MessageBodyReader<T>) provider;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T> MessageBodyWriter<T> getMessageBodyWriter(final Class<T> type,
            final Type genericType,
            final Annotation[] annotations,
            final MediaType mediaType) {

        for (final MessageBodyWriter<?> provider : messageBodyWriters) {
            if (provider.isWriteable(type, genericType, annotations, mediaType)) {
                return (MessageBodyWriter<T>) provider;
            }
        }
        return null;
    }

}
