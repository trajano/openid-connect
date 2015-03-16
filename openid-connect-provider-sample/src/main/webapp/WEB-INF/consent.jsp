<%@ page session="false" pageEncoding="utf8"
	contentType="text/html; charset=utf8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
consent page
<form action="doConsent" method="post" >
<input type="hidden" name="request" value="${param.request}" />
The client ${requestScope.requestObject.clientId} is looking for ${requestScope.requestObject.scopes}. 
<input type="submit" value="consent" />
</form>