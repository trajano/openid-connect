<%@ page session="false" pageEncoding="utf8"
	contentType="text/html; charset=utf8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
Logout Page
<form action="V1/end/confirm" method="post" >
<input type="hidden" name="nonce" value="${param.nonce}" />
<p>Do you want to logout?</p>
<input type="radio" name="logout" value="true" checked="checked">Yes<br>
<input type="radio" name="logout" value="false">No
<input type="submit" value="logout" />
</form>