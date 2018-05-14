<!--
~ Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
<%@ page import="org.wso2.carbon.CarbonConstants" %>
<%@ page import="org.wso2.carbon.identity.oauth.common.OAuthConstants" %>
<%@ page import="org.wso2.carbon.identity.oauth.stub.dto.OAuthConsumerAppDTO" %>
<%@ page import="org.wso2.carbon.identity.oauth.ui.client.OAuthAdminClient" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIMessage" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIUtil" %>
<%@ page import="org.wso2.carbon.utils.ServerConstants" %>
<%@ page import="java.util.ResourceBundle"%>

<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib uri="http://wso2.org/projects/carbon/taglibs/carbontags.jar" prefix="carbon" %>


<jsp:include page="../dialog/display_messages.jsp"/>

<%
    String httpMethod = request.getMethod();
    boolean isHashDisabled = false;
    if (!"post".equalsIgnoreCase(httpMethod)) {
        response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        return;
    }

    String consumerkey = request.getParameter("consumerkey");
    String appName = request.getParameter("appName");

    OAuthConsumerAppDTO app = null;
    String forwardTo = null;
    String BUNDLE = "org.wso2.carbon.identity.oauth.ui.i18n.Resources";
    ResourceBundle resourceBundle = ResourceBundle.getBundle(BUNDLE, request.getLocale());
    String applicationSPName = null;
    OAuthAdminClient client = null;
    String action = null;

    try {

        applicationSPName = request.getParameter("appName");
        session.setAttribute("application-sp-name", applicationSPName);
        action = request.getParameter("action");

        String cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_COOKIE);
        String backendServerURL = CarbonUIUtil.getServerURL(config.getServletContext(), session);
        ConfigurationContext configContext =
                (ConfigurationContext) config.getServletContext()
                        .getAttribute(CarbonConstants.CONFIGURATION_CONTEXT);
        client = new OAuthAdminClient(cookie, backendServerURL, configContext);
        isHashDisabled = client.isHashDisabled();

        if (appName != null) {
            app = client.getOAuthApplicationDataByAppName(appName);
        } else {
            app = client.getOAuthApplicationData(consumerkey);
        }

        OAuthConsumerAppDTO consumerApp = null;
        if (OAuthConstants.ACTION_REGENERATE.equalsIgnoreCase(action)) {
            String oauthAppState = client.getOauthApplicationState(consumerkey);
            if (isHashDisabled) {
                client.regenerateSecretKey(consumerkey);
            } else {
                consumerApp = client.regenerateAndRetrieveOauthSecretKey(consumerkey);
            }
            if(OAuthConstants.OauthAppStates.APP_STATE_REVOKED.equalsIgnoreCase(oauthAppState)) {
                client.updateOauthApplicationState(consumerkey, OAuthConstants.OauthAppStates.APP_STATE_ACTIVE);
            }
            if (isHashDisabled) {
                app.setOauthConsumerSecret(client.getOAuthApplicationData(consumerkey).getOauthConsumerSecret());
                CarbonUIMessage.sendCarbonUIMessage("Client Secret successfully updated for Client ID: " + consumerkey,
                    CarbonUIMessage.INFO, request);
            } else {
                app.setOauthConsumerSecret(consumerApp.getOauthConsumerSecret());
            }
        } else if (OAuthConstants.ACTION_REVOKE.equalsIgnoreCase(action)) {
            String oauthAppState = client.getOauthApplicationState(consumerkey);
            if(OAuthConstants.OauthAppStates.APP_STATE_REVOKED.equalsIgnoreCase(oauthAppState)) {
                CarbonUIMessage.sendCarbonUIMessage("Application is already revoked.",
                        CarbonUIMessage.INFO, request);
            } else {
                client.updateOauthApplicationState(consumerkey, OAuthConstants.OauthAppStates.APP_STATE_REVOKED);
                CarbonUIMessage.sendCarbonUIMessage("Application successfully revoked.",CarbonUIMessage.INFO, request);
            }
        }

    } catch (Exception e) {
        String message = resourceBundle.getString("error.while.loading.user.application.data");
        CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.ERROR, request);
        forwardTo = "../admin/error.jsp";
%>


<%
    }
    if ((action != null) && ("revoke".equalsIgnoreCase(action) || "regenerate".equalsIgnoreCase(action))) {
        session.setAttribute("oauth-consum-secret", app.getOauthConsumerSecret());

        String returnString =
                "../application/configure-service-provider.jsp?action=" + action + "&display=oauthapp&spName=" +
                        applicationSPName + "&oauthapp=" + app.getOauthConsumerKey() +
                        "&isHashDisabled=" + isHashDisabled + "";

            response.addHeader("redirectUrl",returnString);

    }
%>