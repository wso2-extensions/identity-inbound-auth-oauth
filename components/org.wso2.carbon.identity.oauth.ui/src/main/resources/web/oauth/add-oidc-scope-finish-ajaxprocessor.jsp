<%--
  Copyright (c) 2018 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.

   WSO2 Inc. licenses this file to you under the Apache License,
   Version 2.0 (the "License"); you may not use this file except
   in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing,
   software distributed under the License is distributed on an
   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
   KIND, either express or implied.  See the License for the
   specific language governing permissions and limitations
   under the License.
  --%>

<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@page import="org.json.JSONObject" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIMessage" %>
<%@ page import="java.text.MessageFormat" %>
<%@ page import="java.util.ResourceBundle" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIUtil" %>
<%@ page import="org.wso2.carbon.identity.oauth.ui.client.OAuthAdminClient" %>
<%@ page import="org.wso2.carbon.utils.ServerConstants" %>
<%@ page import="org.wso2.carbon.CarbonConstants" %>
<%@ page import="org.apache.axis2.context.ConfigurationContext" %>
<%@ page import="org.wso2.carbon.context.PrivilegedCarbonContext" %>
<%@ page import="org.wso2.carbon.identity.core.util.IdentityTenantUtil" %>
<%@ page import="static org.wso2.carbon.identity.oauth.ui.util.OAuthUIConstants.SCOPE_NAME" %>
<%@ page import="org.apache.commons.lang.StringUtils" %>
<%@ page import="static org.wso2.carbon.identity.oauth.ui.util.OAuthUIConstants.CLAIM_URI" %>
<%@ page import="java.util.Arrays" %>
<jsp:include page="../dialog/display_messages.jsp"/>

<%
    String httpMethod = request.getMethod();
    if (!"post".equalsIgnoreCase(httpMethod)) {
        response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        return;
    }
    String scopeName = null;
    int categoryCount = 0;
    String forwardTo = "add-oidc-scope.jsp";
    String BUNDLE = "org.wso2.carbon.identity.oauth.ui.i18n.Resources";
    ResourceBundle resourceBundle = ResourceBundle.getBundle(BUNDLE, request.getLocale());
    
    try {
        String serverURL = CarbonUIUtil.getServerURL(config.getServletContext(), session);
        ConfigurationContext configContext = (ConfigurationContext)
                config.getServletContext().getAttribute(CarbonConstants.CONFIGURATION_CONTEXT);
        String cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_COOKIE);
        OAuthAdminClient oAuthAdminClient = new OAuthAdminClient(cookie, serverURL, configContext);
        
        scopeName = request.getParameter(SCOPE_NAME);
        String claimRowCount = request.getParameter("claimrow_name_count");
        
        if (StringUtils.isNotBlank(claimRowCount)) {
            categoryCount = Integer.parseInt(claimRowCount);
        }
        String[] claims = new String[categoryCount];
        for (int i = 0; i < categoryCount; i++) {
            String claimInfo = request.getParameter("claimrow_name_wso2_" + i);
            if (StringUtils.isNotBlank(claimInfo)) {
                JSONObject jsonObject = new JSONObject(claimInfo);
                String oidcClaimName = null;
                if (jsonObject.get(CLAIM_URI) != null && jsonObject.get(CLAIM_URI) instanceof String) {
                    oidcClaimName = (String) jsonObject.get(CLAIM_URI);
                }
                if (StringUtils.isNotBlank(oidcClaimName) && !Arrays.asList(claims).contains(oidcClaimName)) {
                    claims[i] = oidcClaimName;
                }
            }
        }
        boolean isScopeExist = oAuthAdminClient.isScopeExist(scopeName);
        String message;
        String messageType;
        if (!isScopeExist) {
            oAuthAdminClient.addScope(scopeName, claims);
            message = MessageFormat.format(resourceBundle.getString("scope.add.successful"), scopeName);
            messageType = CarbonUIMessage.INFO;
            forwardTo = "list-oidc-scopes.jsp";
        } else {
            message = MessageFormat.format(resourceBundle.getString("scope.is.existing"), scopeName);
            messageType = CarbonUIMessage.ERROR;
        }
        CarbonUIMessage.sendCarbonUIMessage(message, messageType, request);
        
    } catch (Exception e) {
        String message = MessageFormat.format(resourceBundle.getString("error.while.saving.scope.info"), scopeName);
        CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.ERROR, request);
    }
%>

<script type="text/javascript">
    function forward() {
        location.href = "<%=forwardTo%>";
    }

    forward();
</script>
