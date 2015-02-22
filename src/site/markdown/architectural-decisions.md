Architectural Decisions
=======================

*Servlets are used rather than JAX-RS for the REST API.*  When I originally
built the provider, I had used JAX-RS API thinking it would save a bit of
work, in the end it didn't really add much more capability than the Servlet
API with the exception of  `UriBuilder` which is used extensively and
the JSON APIs.