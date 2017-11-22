<!--
 ~ Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 ~
 ~ WSO2 Inc. licenses this file to you under the Apache License,
 ~ Version 2.0 (the "License"); you may not use this file except
 ~ in compliance with the License.
 ~ You may obtain a copy of the License at
 ~
 ~    http://www.apache.org/licenses/LICENSE-2.0
 ~
 ~ Unless required by applicable law or agreed to in writing,
 ~ software distributed under the License is distributed on an
 ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 ~ KIND, either express or implied.  See the License for the
 ~ specific language governing permissions and limitations
 ~ under the License.
 -->

<%@ page import="org.apache.axis2.context.ConfigurationContext"%>
<%@ page import="org.owasp.encoder.Encode" %>
<%@ page import="org.wso2.carbon.CarbonConstants"%>
<%@ page import="org.wso2.carbon.identity.oauth.common.OAuthConstants"%>
<%@ page import="org.wso2.carbon.identity.oauth.stub.dto.OAuthConsumerAppDTO"%>
<%@ page import="org.wso2.carbon.identity.oauth.ui.client.OAuthAdminClient"%>
<%@ page import="org.wso2.carbon.ui.CarbonUIMessage"%>
<%@ page import="org.wso2.carbon.ui.CarbonUIUtil"%>
<%@ page import="org.wso2.carbon.utils.ServerConstants"%>

<%@ page import="java.util.ResourceBundle" %>
<%@ page import="org.wso2.carbon.identity.oauth.ui.util.OAuthUIUtil" %>

<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<%@ taglib uri="http://wso2.org/projects/carbon/taglibs/carbontags.jar" prefix="carbon"%>

<script type="text/javascript" src="extensions/js/vui.js"></script>
<script type="text/javascript" src="../extensions/core/js/vui.js"></script>
<script type="text/javascript" src="../admin/js/main.js"></script>

<jsp:include page="../dialog/display_messages.jsp" />

<%
    String httpMethod = request.getMethod();
    if (!"post".equalsIgnoreCase(httpMethod)) {
        response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        return;
    }

    String consumerkey = request.getParameter("consumerkey");
    String callback = request.getParameter("callback");
    String applicationName = request.getParameter("application");
    String consumersecret = request.getParameter("consumersecret");
    String oauthVersion = request.getParameter("oauthVersion");
    String userAccessTokenExpiryTime = request.getParameter("userAccessTokenExpiryTime");
    String applicationAccessTokenExpiryTime = request.getParameter("applicationAccessTokenExpiryTime");
    String refreshTokenExpiryTime = request.getParameter("refreshTokenExpiryTime");
    String grants;
   	StringBuffer buff = new StringBuffer();
    boolean pkceMandatory = false;
    boolean pkceSupportPlain = false;
    boolean tokenBinding = false;

    if(request.getParameter("pkce") != null) {
        pkceMandatory = true;
    }
    if(request.getParameter("pkce_plain") != null) {
        pkceSupportPlain = true;
    }
    if(request.getParameter("tb") !=null){
        tokenBinding = true;
    }

	String forwardTo = "index.jsp";
    String BUNDLE = "org.wso2.carbon.identity.oauth.ui.i18n.Resources";
	ResourceBundle resourceBundle = ResourceBundle.getBundle(BUNDLE, request.getLocale());
	OAuthConsumerAppDTO app = new OAuthConsumerAppDTO();
	
	String spName = (String) session.getAttribute("application-sp-name");
	session.removeAttribute("application-sp-name");
	boolean isError = false;
	
    try {
        if (OAuthUIUtil.isValidURI(callback)) {
            String cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_COOKIE);
            String backendServerURL = CarbonUIUtil.getServerURL(config.getServletContext(), session);
            ConfigurationContext configContext =
                    (ConfigurationContext) config.getServletContext().getAttribute(CarbonConstants.CONFIGURATION_CONTEXT);
            OAuthAdminClient client = new OAuthAdminClient(cookie, backendServerURL, configContext);
            app.setOauthConsumerKey(consumerkey);
            app.setOauthConsumerSecret(consumersecret);
            app.setCallbackUrl(callback);
            app.setApplicationName(applicationName);
            app.setOAuthVersion(oauthVersion);
            app.setPkceMandatory(pkceMandatory);
            app.setPkceSupportPlain(pkceSupportPlain);
            app.setUserAccessTokenExpiryTime(Long.parseLong(userAccessTokenExpiryTime));
            app.setApplicationAccessTokenExpiryTime(Long.parseLong(applicationAccessTokenExpiryTime));
            app.setRefreshTokenExpiryTime(Long.parseLong(refreshTokenExpiryTime));
            app.setTbMandatory(tokenBinding);
            String[] grantTypes = client.getAllowedOAuthGrantTypes();
            for (String grantType : grantTypes) {
                String grant = request.getParameter("grant_" + grantType);
                if (grant != null) {
                    buff.append(grantType + " ");
                }
            }
            grants = buff.toString();
            if (OAuthConstants.OAuthVersions.VERSION_2.equals(oauthVersion)) {
                app.setGrantTypes(grants);
            }
            client.updateOAuthApplicationData(app);
            String message = resourceBundle.getString("app.updated.successfully");
            CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.INFO, request);
        } else {
            isError = false;
            String message = resourceBundle.getString("callback.is.not.url");
            CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.ERROR, request);
        }

    } catch (Exception e) {
    	isError = false;
    	String message = resourceBundle.getString("error.while.updating.app");
    	CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.ERROR, request,e);
        forwardTo ="../admin/error.jsp";
    }
%>

<script>

<%
boolean qpplicationComponentFound = CarbonUIUtil.isContextRegistered(config, "/application/");
if (qpplicationComponentFound) {
	if (!isError) {
%>
    location.href = '../application/configure-service-provider.jsp?action=update&display=oauthapp&spName=<%=Encode.forUriComponent(spName)%>&oauthapp=<%=Encode.forUriComponent(consumerkey)%>';
<%  } else { %>
    location.href = '../application/configure-service-provider.jsp?action=cancel&display=oauthapp&spName=<%=Encode.forUriComponent(spName)%>';
<%
    }
}else {
%>
    location.href = '<%=forwardTo%>';
<% } %>

</script>

<script type="text/javascript">
    forward();
</script>