<%@ page session="false" pageEncoding="utf8"
	contentType="text/html; charset=utf8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
LOGIN page
<form action="doLogin" method="post" >
<input type="hidden" name="acr_values" value="${param.acr_values}" />
<input type="hidden" name="client_id" value="${param.client_id}" />
<input type="hidden" name="display" value="${param.display}" />
<input type="hidden" name="id_token_hint" value="${param.id_token_hint}" />
<input type="hidden" name="login_hint" value="${param.login_hint}" />
<input type="hidden" name="max_age" value="${param.max_age}" />
<input type="hidden" name="nonce" value="${param.nonce}" />
<input type="hidden" name="prompt" value="${param.prompt}" />
<input type="hidden" name="redirect_uri" value="${param.redirect_uri}" />
<input type="hidden" name="response_mode" value="${param.response_mode}" />
<input type="hidden" name="response_type" value="${param.response_type}" />
<input type="hidden" name="scope" value="${param.scope}" />
<input type="hidden" name="state" value="${param.state}" />
<input type="hidden" name="ui_locales" value="${param.ui_locales}" />
User name: <input type="text" name="username">
<input type="submit" value="login" />
</form>