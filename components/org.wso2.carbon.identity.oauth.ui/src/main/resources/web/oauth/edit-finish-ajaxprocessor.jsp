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
<%@ page import="org.wso2.carbon.identity.core.util.IdentityUtil" %>

<%@ page import="java.util.ResourceBundle" %>
<%@ page import="org.wso2.carbon.identity.oauth.ui.util.OAuthUIUtil" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.util.List" %>
<%@ page import="java.util.Objects" %>

<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<%@ taglib uri="http://wso2.org/projects/carbon/taglibs/carbontags.jar" prefix="carbon"%>

<script type="text/javascript" src="extensions/js/vui.js"></script>
<script type="text/javascript" src="../extensions/core/js/vui.js"></script>
<script type="text/javascript" src="../admin/js/main.js"></script>

<jsp:include page="../dialog/display_messages.jsp" />

<%
    boolean isHashDisabled = false;
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
    String idTokenExpiryTime = request.getParameter("idTokenExpiryTime");
    String tokenType = request.getParameter("tokenType");
    String logoutMechanism = request.getParameter("logoutMechanism");
    String logoutUrl = request.getParameter("logoutUrl");
    String isRenewRefreshTokenEnabled = request.getParameter("renewRefreshTokenPerApp");
    String grants;
   	StringBuffer buff = new StringBuffer();
    boolean pkceMandatory = false;
    boolean pkceSupportPlain = false;
    boolean bypassClientCredentials = false;

    if (request.getParameter("pkce") != null) {
        pkceMandatory = true;
    }

    if (request.getParameter("pkce_plain") != null) {
        pkceSupportPlain = true;
    }

    if (request.getParameter("bypass_client_credentials") != null) {
        bypassClientCredentials = true;
    }

    // OIDC related properties
    boolean isRequestObjectSignatureValidated = Boolean.parseBoolean(request.getParameter("validateRequestObjectSignature"));
    boolean isIdTokenEncrypted = Boolean.parseBoolean(request.getParameter("encryptIdToken"));
    String idTokenEncryptionAlgorithm = request.getParameter("idTokenEncryptionAlgorithm");
    String idTokenEncryptionMethod = request.getParameter("idTokenEncryptionMethod");
    
    String forwardTo = "index.jsp";
    String BUNDLE = "org.wso2.carbon.identity.oauth.ui.i18n.Resources";
	ResourceBundle resourceBundle = ResourceBundle.getBundle(BUNDLE, request.getLocale());
	OAuthConsumerAppDTO app = new OAuthConsumerAppDTO();
    
    String spName = request.getParameter("application");
	boolean isError = false;

    try {
        if (OAuthUIUtil.isValidURI(callback) || callback.startsWith(OAuthConstants.CALLBACK_URL_REGEXP_PREFIX)) {
            String cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_COOKIE);
            String backendServerURL = CarbonUIUtil.getServerURL(config.getServletContext(), session);
            ConfigurationContext configContext =
                    (ConfigurationContext) config.getServletContext().getAttribute(CarbonConstants.CONFIGURATION_CONTEXT);
            OAuthAdminClient client = new OAuthAdminClient(cookie, backendServerURL, configContext);
            isHashDisabled = client.isHashDisabled();

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
            app.setIdTokenExpiryTime(Long.parseLong(idTokenExpiryTime));
            app.setTokenType(tokenType);
            String[] grantTypes = client.getAllowedOAuthGrantTypes();
            for (String grantType : grantTypes) {
                String grant = request.getParameter("grant_" + grantType);
                if (grant != null) {
                    buff.append(grantType + " ");
                }
            }
            grants = buff.toString();

            List<String> scopeValidators = new ArrayList<String>();
            String[] allowedValidators = client.getAllowedScopeValidators();
            for (String allowedValidator : allowedValidators) {
                String scopeValidatorValue = request.getParameter(OAuthUIUtil.getScopeValidatorId(allowedValidator));
                if (scopeValidatorValue != null) {
                    scopeValidators.add(allowedValidator);
                }
            }

            if (OAuthConstants.OAuthVersions.VERSION_2.equals(oauthVersion)) {
                app.setGrantTypes(grants);
                app.setScopeValidators(scopeValidators.toArray(new String[scopeValidators.size()]));
            }
            if (Boolean.parseBoolean(request.getParameter("enableAudienceRestriction"))) {
                String audiencesCountParameter = request.getParameter("audiencePropertyCounter");
                if (IdentityUtil.isNotBlank(audiencesCountParameter)) {
                    int audiencesCount = Integer.parseInt(audiencesCountParameter);
                    String[] audiences = request.getParameterValues("audiencePropertyName");
                    if (OAuthConstants.OAuthVersions.VERSION_2.equals(oauthVersion)) {
                        app.setAudiences(audiences);
                    }
                }
            }
            
            app.setRequestObjectSignatureValidationEnabled(isRequestObjectSignatureValidated);
            app.setIdTokenEncryptionEnabled(isIdTokenEncrypted);
            if (isIdTokenEncrypted) {
                app.setIdTokenEncryptionAlgorithm(idTokenEncryptionAlgorithm);
                app.setIdTokenEncryptionMethod(idTokenEncryptionMethod);
            }
            app.setBypassClientCredentials(bypassClientCredentials);

            if (OAuthConstants.OIDCConfigProperties.BACK_CHANNEL_LOGOUT.equalsIgnoreCase(logoutMechanism)) {
                app.setBackChannelLogoutUrl(logoutUrl);
            } else if (OAuthConstants.OIDCConfigProperties.FRONT_CHANNEL_LOGOUT.equalsIgnoreCase(logoutMechanism)) {
                app.setFrontchannelLogoutUrl(logoutUrl);
            }

            if (!Objects.equals(isRenewRefreshTokenEnabled, "notAssigned")) {
                app.setRenewRefreshTokenEnabled(String.valueOf(Boolean.parseBoolean(isRenewRefreshTokenEnabled)));
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
        CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.ERROR, request, e);
        forwardTo = "../admin/error.jsp";
    }
%>

<script>

<%
boolean qpplicationComponentFound = CarbonUIUtil.isContextRegistered(config, "/application/");
if (qpplicationComponentFound) {
	if (!isError) {
%>
    location.href = '../application/configure-service-provider.jsp?action=update&display=oauthapp&spName=<%=Encode.forUriComponent(spName)%>&oauthapp=<%=Encode.forUriComponent(consumerkey)%>&isHashDisabled=<%=Encode.forUriComponent(String.valueOf(isHashDisabled))%>';
<%  } else { %>
    location.href = '../application/configure-service-provider.jsp?action=cancel&display=oauthapp&spName=<%=Encode.forUriComponent(spName)%>&isHashDisabled=<%=Encode.forUriComponent(String.valueOf(isHashDisabled))%>';
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