Architectural Decisions
=======================

*Servlets are used rather than JAX-RS for the REST API.*  When I originally
built the provider, I had used JAX-RS API thinking it would save a bit of
work, in the end it didn't really add much more capability than the Servlet
API with the exception of  `UriBuilder` which is used extensively and
the JSON APIs.

[Shiro][] is used to handle the authentication on the provider as it provides
a rich API to handle authentication semantics already.  However, the scope
of [Shiro][] is limited to the provider only.  This was chosen over JAAS form
based login as finer grained control was needed.

[Shiro]: http://shiro.apache.org/