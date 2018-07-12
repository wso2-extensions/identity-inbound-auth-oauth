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
<%@page import="org.apache.commons.lang.StringUtils" %>
<%@page import="org.json.JSONObject" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIMessage" %>
<%@ page import="java.util.ResourceBundle" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIUtil" %>
<%@ page import="org.wso2.carbon.identity.oauth.ui.client.OAuthAdminClient" %>
<%@ page import="org.wso2.carbon.utils.ServerConstants" %>
<%@ page import="org.wso2.carbon.CarbonConstants" %>
<%@ page import="org.apache.axis2.context.ConfigurationContext" %>
<%@ page import="org.wso2.carbon.context.PrivilegedCarbonContext" %>
<%@ page import="org.wso2.carbon.identity.core.util.IdentityTenantUtil" %>
<%@ page import="java.text.MessageFormat" %>
<%@ page import="static org.wso2.carbon.identity.oauth.ui.util.OAuthUIConstants.CLAIM_URI" %>
<%@ page import="static org.wso2.carbon.identity.oauth.ui.util.OAuthUIConstants.SCOPE_NAME" %>
<jsp:include page="../dialog/display_messages.jsp"/>

<%
    String httpMethod = request.getMethod();
    if (!"post".equalsIgnoreCase(httpMethod)) {
        response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        return;
    }
    
    String scopeName = null;
    String BUNDLE = "org.wso2.carbon.identity.oauth.ui.i18n.Resources";
    ResourceBundle resourceBundle = ResourceBundle.getBundle(BUNDLE, request.getLocale());
    String forwardTo = null;
    try {
        String serverURL = CarbonUIUtil.getServerURL(config.getServletContext(), session);
        ConfigurationContext configContext = (ConfigurationContext)
                config.getServletContext().getAttribute(CarbonConstants.CONFIGURATION_CONTEXT);
        String cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_COOKIE);
        OAuthAdminClient oAuthAdminClient = new OAuthAdminClient(cookie, serverURL, configContext);
        boolean isAdd = Boolean.parseBoolean(request.getParameter("add"));
        scopeName = request.getParameter(SCOPE_NAME);
        int categoryCount = Integer.parseInt(request.getParameter("claimrow_name_count"));
        String oidcClaim = null;
        String[] claims = new String[categoryCount];
        for (int i = 0; i < categoryCount; i++) {
            String claimInfo = request.getParameter("claimrow_name_wso2_" + i);
            if (StringUtils.isNotBlank(claimInfo)) {
                JSONObject jsonObject = new JSONObject(claimInfo);
                if (jsonObject.get(CLAIM_URI) != null && jsonObject.get(CLAIM_URI) instanceof String) {
                    oidcClaim = (String) jsonObject.get(CLAIM_URI);
                }
            }
            
            if (StringUtils.isNotBlank(oidcClaim)) {
                claims[i] = oidcClaim;
            }
        }
        
        oAuthAdminClient.updateScope(scopeName, claims, null);
        String message = MessageFormat.format(resourceBundle.getString("updated.the.scope.successfully"), scopeName);
        CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.INFO, request);
        
        if (isAdd) {
            forwardTo = "add-oidc-claims.jsp?scopeName=" + scopeName;
        } else {
            forwardTo = "list-oidc-scopes.jsp";
        }
    } catch (Exception e) {
        String message = MessageFormat.format(resourceBundle.getString("failed.to.update.the.scope"), scopeName);
        CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.ERROR, request);
    }
%>

<script type="text/javascript">
    function forward() {
        location.href = "<%=forwardTo%>";
    }

    forward();
</script>
