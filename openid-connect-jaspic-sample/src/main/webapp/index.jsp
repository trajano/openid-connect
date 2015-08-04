index
<%= request.getUserPrincipal() %>
ROLE <%= request.isUserInRole("https://localhost:8443/") %>
ROLE <%= request.isUserInRole("users") %>
<a href="test.jsp">test page</a>
<a href="token">token</a>
<a href="userinfo">userinfo</a>
<a href="logout">Logout</a>