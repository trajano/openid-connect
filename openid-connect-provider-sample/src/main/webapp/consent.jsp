<%@ page session="false" pageEncoding="utf8"
	contentType="text/html; charset=utf8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
consent page
<form action="doConsent" method="post" >
<input type="hidden" name="request" value="${param.request}" />
If we had a servlet we can extract the data from the authentication request and have a better looking consent page than this.
<input type="submit" value="consent" />
</form>