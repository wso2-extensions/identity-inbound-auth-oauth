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
<%@ page import="org.wso2.carbon.identity.core.util.IdentityUtil"%>
<%@ page import="org.wso2.carbon.identity.oauth.common.OAuthConstants"%>
<%@ page import="org.wso2.carbon.identity.oauth.stub.dto.OAuthConsumerAppDTO"%>
<%@ page import="org.wso2.carbon.identity.oauth.ui.client.OAuthAdminClient"%>
<%@ page import="org.wso2.carbon.identity.oauth.ui.util.OAuthUIUtil"%>
<%@ page import="org.wso2.carbon.ui.CarbonUIMessage" %>

<%@ page import="org.wso2.carbon.ui.CarbonUIUtil" %>
<%@ page import="org.wso2.carbon.utils.ServerConstants" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.util.List" %>
<%@ page import="java.util.ResourceBundle" %>
<%@ page import="java.util.Objects" %>

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

    boolean isHashDisabled = false;
    String applicationName = request.getParameter("application");
    String callback = request.getParameter("callback");
    String oauthVersion = request.getParameter("oauthVersion");
    String userAccessTokenExpiryTime = request.getParameter("userAccessTokenExpiryTime");
    String applicationAccessTokenExpiryTime = request.getParameter("applicationAccessTokenExpiryTime");
    String refreshTokenExpiryTime = request.getParameter("refreshTokenExpiryTime");
    String idTokenExpiryTime = request.getParameter("idTokenExpiryTime");
    String tokenType = request.getParameter("tokenType");
    String logoutMechanism = request.getParameter("logoutMechanism");
    String logoutUrl = request.getParameter("logoutUrl");
    String isRenewRefreshTokenEnabled = request.getParameter("renewRefreshTokenPerApp");

	boolean pkceMandatory = false;
	boolean pkceSupportPlain = false;
	boolean bypassClientCredentials = false;

	if(request.getParameter("pkce") != null) {
		pkceMandatory = true;
	}

	if(request.getParameter("pkce_plain") != null) {
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
	OAuthConsumerAppDTO consumerApp = null;

    try {
        if (OAuthUIUtil.isValidURI(callback) || callback.startsWith(OAuthConstants.CALLBACK_URL_REGEXP_PREFIX)) {
            String cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_COOKIE);
            String backendServerURL = CarbonUIUtil.getServerURL(config.getServletContext(), session);
            ConfigurationContext configContext =
                    (ConfigurationContext) config.getServletContext()
                            .getAttribute(CarbonConstants.CONFIGURATION_CONTEXT);
            OAuthAdminClient client = new OAuthAdminClient(cookie, backendServerURL, configContext);
            isHashDisabled = client.isHashDisabled();
            app.setApplicationName(applicationName);
            app.setCallbackUrl(callback);
            app.setOAuthVersion(oauthVersion);
            app.setUserAccessTokenExpiryTime(Long.parseLong(userAccessTokenExpiryTime));
            app.setApplicationAccessTokenExpiryTime(Long.parseLong(applicationAccessTokenExpiryTime));
            app.setRefreshTokenExpiryTime(Long.parseLong(refreshTokenExpiryTime));
            app.setIdTokenExpiryTime(Long.parseLong(idTokenExpiryTime));
            app.setTokenType(tokenType);

            if (OAuthConstants.OIDCConfigProperties.BACK_CHANNEL_LOGOUT.equalsIgnoreCase(logoutMechanism)) {
                app.setBackChannelLogoutUrl(logoutUrl);
            } else if (OAuthConstants.OIDCConfigProperties.FRONT_CHANNEL_LOGOUT.equalsIgnoreCase(logoutMechanism)) {
                app.setFrontchannelLogoutUrl(logoutUrl);
            }

            String grants;
            StringBuffer buff = new StringBuffer();
            String[] grantTypes = client.getAllowedOAuthGrantTypes();
            for (String grantType : grantTypes) {
                String grant = request.getParameter("grant_" + grantType);
                if (grant != null) {
                    buff.append(grantType + " ");
                }
            }
            grants = buff.toString();

            List<String> registeredScopeValidators = new ArrayList<String>();
            String[] allowedValidators = client.getAllowedScopeValidators();
            for (String allowedValidator : allowedValidators) {
                String scopeValidatorValue = request.getParameter(OAuthUIUtil.getScopeValidatorId(allowedValidator));
                if (scopeValidatorValue != null) {
                    registeredScopeValidators.add(allowedValidator);
                }
            }

            if (OAuthConstants.OAuthVersions.VERSION_2.equals(oauthVersion)) {
                app.setGrantTypes(grants);
                app.setScopeValidators(registeredScopeValidators.toArray(new String[registeredScopeValidators.size()]));
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
            app.setPkceMandatory(pkceMandatory);
            app.setPkceSupportPlain(pkceSupportPlain);
            app.setBypassClientCredentials(bypassClientCredentials);

            // Set OIDC related configuration properties.
            app.setRequestObjectSignatureValidationEnabled(isRequestObjectSignatureValidated);
            app.setIdTokenEncryptionEnabled(isIdTokenEncrypted);
            if (isIdTokenEncrypted) {
                app.setIdTokenEncryptionAlgorithm(idTokenEncryptionAlgorithm);
                app.setIdTokenEncryptionMethod(idTokenEncryptionMethod);
            }
            if (!Objects.equals(isRenewRefreshTokenEnabled, "notAssigned")) {
                app.setRenewRefreshTokenEnabled(String.valueOf(Boolean.parseBoolean(isRenewRefreshTokenEnabled)));
            }

            if (isHashDisabled) {
                client.registerOAuthApplicationData(app);
                consumerApp = client.getOAuthApplicationDataByAppName(applicationName);
                String message = resourceBundle.getString("app.added.successfully");
                CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.INFO, request);
            } else {
                consumerApp = client.registerAndRetrieveOAuthApplicationData(app);
            }
        } else {
            isError = true;
            String message = resourceBundle.getString("callback.is.not.url");
            CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.ERROR, request);
        }
    } catch (Exception e) {
        isError = true;
        String message = resourceBundle.getString("error.while.adding.app") + " : " + e.getMessage();
        CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.ERROR, request, e);
    }
%>

<script>

<%

boolean qpplicationComponentFound = CarbonUIUtil.isContextRegistered(config, "/application/");
if (qpplicationComponentFound) {
	if (!isError) {
		session.setAttribute("oauth-consum-secret", consumerApp.getOauthConsumerSecret());
%>
    location.href = '../application/configure-service-provider.jsp?action=update&display=oauthapp&spName=<%=Encode.forUriComponent(spName)%>&oauthapp=<%=Encode.forUriComponent(consumerApp.getOauthConsumerKey())%>&isHashDisabled=<%=Encode.forUriComponent(String.valueOf(isHashDisabled))%>&operation=add';
<% } else { %>
    location.href = '../application/configure-service-provider.jsp?display=oauthapp&spName=<%=Encode.forUriComponent(spName)%>&action=cancel&isHashDisabled=<%=Encode.forUriComponent(String.valueOf(isHashDisabled))%>&operation=add';
<% }
} else {%>
    location.href = 'index.jsp';
<% } %>

</script>


<script type="text/javascript">
    forward();
</script>