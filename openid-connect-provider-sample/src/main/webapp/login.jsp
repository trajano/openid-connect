<%@ page session="false" pageEncoding="utf8"
	contentType="text/html; charset=utf8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
LOGIN page
<form action="doLogin" method="post" >
<input type="hidden" name="request" value="${param.request}" />
User name: <input type="text" name="username">
<input type="submit" value="login" />
</form>