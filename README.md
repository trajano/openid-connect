OpenID Connect
==============

This is an implementation of the OpenID Connect implementation using Java EE
core technologies such as Servlets and JASPIC.  This was extracted from the
[server-auth-modules][] project in order to streamline the code base for
client and server side components.

It has the following components:

* openid-connect-core : this contains all the common elements for both client
  and server.  The naming of `core` was intentional as this provides all the
  OpenID Connect core terms, objects, messages as per the [OpenID Connect specification][].

* openid-connect-jaspic-module : this is an implementation of an OpenID Connect
  client as a JASPIC ServerAuthModule.  This provides a standards based
  authentication implementation which does not include any external dependencies.
  
* openid-connect-provider : this provides the REST API implementation and
  Java interfaces that are necessary to set up an OpenID Provider.  It is a
  JAR file that is intended to be included in a WAR project that would be
  responsible for exposing the API using the `web.xml` and `Application`

* openid-connect-provider-sample: this is a sample OpenID Provider as a
  WAR file used to perform testing.

Specifications Implemented
--------------------------
[OpenID Specifications][] that have been implemented are:

* [OpenID Connect Core][]
* [OpenID Connect Discovery][] only the `.well-known/openid-configuration`
* [OAuth 2.0 Multiple Response Type Encoding Practices][]
* [OpenID Connect HTTP Based Logout][]
* [OAuth 2.0 Form Post Response Mode][]

[server-auth-modules]: http://site.trajano.net/server-auth-modules
[OpenID Connect specification]: http://openid.net/connect/
[OpenID Connect Discovery]: http://openid.net/specs/openid-connect-discovery-1_0.html
[OAuth 2.0 Multiple Response Type Encoding Practices]: http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html
[OpenID Specifications]: https://openid.net/developers/specs/
[OpenID Connect HTTP Based Logout]: http://openid.net/specs/openid-connect-logout-1_0.html
[OpenID Connect Core]: http://openid.net/specs/openid-connect-core-1_0.html
[OAuth 2.0 Form Post Response Mode]: http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
