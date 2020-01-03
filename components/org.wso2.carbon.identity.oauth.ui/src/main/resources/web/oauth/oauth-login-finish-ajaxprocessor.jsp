<!--
~ Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
~
~ WSO2 Inc. licenses this file to you under the Apache License,
~ Version 2.0 (the "License"); you may not use this file except
~ in compliance with the License.
~ You may obtain a copy of the License at
~
~ http://www.apache.org/licenses/LICENSE-2.0
~
~ Unless required by applicable law or agreed to in writing,
~ software distributed under the License is distributed on an
~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
~ KIND, either express or implied. See the License for the
~ specific language governing permissions and limitations
~ under the License.
-->

<%@ page import="org.apache.axis2.context.ConfigurationContext" %>
<%@ page import="org.owasp.encoder.Encode" %>
<%@ page import="org.wso2.carbon.CarbonConstants" %>
<%@ page import="org.wso2.carbon.identity.core.util.IdentityUtil" %>
<%@ page import="org.wso2.carbon.identity.oauth.common.OAuthConstants" %>
<%@ page import="org.wso2.carbon.identity.oauth.stub.types.Parameters" %>
<%@ page import="org.wso2.carbon.identity.oauth.ui.client.OAuthServiceClient" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIMessage" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIUtil" %>

<%@ page import="org.wso2.carbon.utils.ServerConstants" %>
<%@ page import="java.util.ResourceBundle" %>

<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib uri="http://wso2.org/projects/carbon/taglibs/carbontags.jar" prefix="carbon" %>

<script type="text/javascript" src="extensions/js/vui.js"></script>
<script type="text/javascript" src="../extensions/core/js/vui.js"></script>
<script type="text/javascript" src="../admin/js/main.js"></script>

<jsp:include page="../dialog/display_messages.jsp"/>

<%
    String httpMethod = request.getMethod();
    if (!"post".equalsIgnoreCase(httpMethod)) {
        response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        return;
    }
    
    String oauthUserName = request.getParameter("oauth_user_name");
    String oauthUserPassword = request.getParameter("oauth_user_password");
    String forwardTo = "index.jsp";
    String BUNDLE = "org.wso2.carbon.identity.oauth.ui.i18n.Resources";
    ResourceBundle resourceBundle = ResourceBundle.getBundle(BUNDLE, request.getLocale());
    Parameters params = new Parameters();
    Parameters resp = null;
    
    try {
        String cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_COOKIE);
        String backendServerURL = CarbonUIUtil.getServerURL(config.getServletContext(), session);
        ConfigurationContext configContext =
                (ConfigurationContext) config.getServletContext().getAttribute(CarbonConstants.CONFIGURATION_CONTEXT);
        OAuthServiceClient client = new OAuthServiceClient(backendServerURL, configContext);
        params.setAuthorizedbyUserName(oauthUserName);
        params.setAuthorizedbyUserPassword(oauthUserPassword);
        params.setOauthToken((String) session.getAttribute("oauth_req_token"));
        resp = client.authorizeOauthRequestToken(params);
        session.removeAttribute("oauth_req_token");
        session.removeAttribute("oauth_scope");
        session.removeAttribute("oauth_app_name");
        forwardTo = Encode.forUriComponent(resp.getOauthCallback()) + "?" + OAuthConstants.OAUTH_TOKEN + "=" +
                Encode.forUriComponent(resp.getOauthToken()) + "&" +
                Encode.forUriComponent(OAuthConstants.OAUTH_VERIFIER) +
                "=" + Encode.forUriComponent(resp.getOauthTokenVerifier());
    } catch (Exception e) {
        String message = resourceBundle.getString("auth.error");
        CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.ERROR, request, e);
        forwardTo = IdentityUtil.getServerURL("/carbon/oauth/oauth-login.jsp", false, true);
    }
%>

<script type="text/javascript">
    function forward() {
        location.href = "<%=forwardTo%>";
    }
</script>

<script type="text/javascript">
    forward();
</script>