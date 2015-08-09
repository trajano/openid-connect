Scope
=====

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
 
Todo
----
1. [OpenID Dynamic Client Registration][1]
2. Make a shaded `openid-connect-jaspic-module` that can be deployed
   as an OSGi bundle.
3. Provide a default token provider implementation using JCache API

[1]: https://openid.net/specs/openid-connect-registration-1_0.html
