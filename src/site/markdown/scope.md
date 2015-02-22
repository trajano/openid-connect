In Scope
--------
1. `/.well-known/openid-configuration`

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
 