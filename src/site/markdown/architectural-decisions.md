Architectural Decisions
=======================

There are three WAR files.  One for OpenID Provider, one for the resource
provider and one that does login.  The login and resource provider will be
samples.

EJBs will d 

*Servlets are used rather than JAX-RS for the REST API.*  When I originally
built the provider, I had used JAX-RS API thinking it would save a bit of
work, in the end it didn't really add much more capability than the Servlet
API with the exception of  `UriBuilder` which is used extensively and
the JSON APIs.

[Shiro][] is used to handle the authentication on the provider sample 
as it provides a rich API to handle authentication semantics already.

[Shiro]: http://shiro.apache.org/