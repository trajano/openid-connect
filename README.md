OpenID Connect
==============

This is an implementation of the OpenID Connect implementation using Java EE
core technologies such as JAX-RS and JASPIC.  This was extracted from the
[server-auth-modules][] project in order to streamline the code base for
client and server side components.

It has the following components:

* openid-connect-core : this contains all the common elements for both client
  and server.  The naming of `core` was intentional as this provides all the
  OpenID Connect core terms, objects, messages as per the [OpenID Connect
  specification].

* openid-connect-jaspic-module : this is an implementation of an OpenID Connect
  client as a JASPIC ServerAuthModule.  This provides a standards based
  authentication implementation which does not include any external dependencies.
  To make it simpler to deploy, it has an assembly target that will combine the
  `openid-connect-core` classes with the ones in here and it also built as an
  OSGi bundle.
  
* openid-connect-provider : this provides the REST API implementation and
  Java interfaces that are necessary to set up an OpenID Provider.  It is a
  JAR file that is intended to be included in a WAR project that would be
  responsible for exposing the API using the `web.xml` and `Application`

* openid-connect-provider-sample: this is a sample OpenID Provider as a
  WAR file used to perform testing.

Out of scope
------------
The following things are not in scope of this project:

1. Realm implementations aside from the properties file driven one.  It is
   expected that users of the library will implement one specific for their
   project to connect to LDAP or a database.

2. A nice login page.  For the samples, a simple login page with user ID
   and password is provided.

3. Client ID/Client Secret maintenance.  It is expected that users of the
   library will implement one specific for their project to manage their own
   client database.

[server-auth-modules]: http://site.trajano.net/server-auth-modules
[OpenID Connect specification]: http://openid.net/connect/
