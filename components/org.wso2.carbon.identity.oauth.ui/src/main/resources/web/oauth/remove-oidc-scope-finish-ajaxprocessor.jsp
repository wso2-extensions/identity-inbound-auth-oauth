<%--
  ~ Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
  ~
  ~ Licensed under the Apache License, Version 2.0 (the "License");
  ~ you may not use this file except in compliance with the License.
  ~ You may obtain a copy of the License at
  ~
  ~ http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing, software
  ~ distributed under the License is distributed on an "AS IS" BASIS,
  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  ~ See the License for the specific language governing permissions and
  ~ limitations under the License
  --%>

<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib uri="http://wso2.org/projects/carbon/taglibs/carbontags.jar" prefix="carbon" %>
<%@ taglib uri="http://www.owasp.org/index.php/Category:OWASP_CSRFGuard_Project/Owasp.CsrfGuard.tld" prefix="csrf" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIMessage" %>
<%@ page import="java.util.ResourceBundle" %>
<%@ page import="org.wso2.carbon.context.PrivilegedCarbonContext" %>
<%@ page import="org.wso2.carbon.identity.core.util.IdentityTenantUtil" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIUtil" %>
<%@ page import="org.apache.axis2.context.ConfigurationContext" %>
<%@ page import="org.wso2.carbon.CarbonConstants" %>
<%@ page import="org.wso2.carbon.utils.ServerConstants" %>
<%@ page import="org.wso2.carbon.identity.oauth.ui.client.OAuthAdminClient" %>
<%@ page import="java.text.MessageFormat" %>
<%@ page import="static org.wso2.carbon.identity.oauth.ui.util.OAuthUIConstants.SCOPE_NAME" %>
<jsp:include page="../dialog/display_messages.jsp"/>

<div id="middle">
    <div id="workArea">
        
        <%
            String httpMethod = request.getMethod();
            if (!"post".equalsIgnoreCase(httpMethod)) {
                response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
                return;
            }
            
            String forwardTo = "list-oidc-scopes.jsp";
            String BUNDLE = "org.wso2.carbon.identity.oauth.ui.i18n.Resources";
            ResourceBundle resourceBundle = ResourceBundle.getBundle(BUNDLE, request.getLocale());
            String scopeName = request.getParameter(SCOPE_NAME);
            
            try {
                String serverURL = CarbonUIUtil.getServerURL(config.getServletContext(), session);
                ConfigurationContext configContext = (ConfigurationContext)
                        config.getServletContext().getAttribute(CarbonConstants.CONFIGURATION_CONTEXT);
                String cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_COOKIE);
                OAuthAdminClient oAuthAdminClient = new OAuthAdminClient(cookie, serverURL, configContext);
                oAuthAdminClient.deleteScope(scopeName);
            } catch (Exception e) {
                String message = MessageFormat.format(resourceBundle.getString("error.while.deleting.scope"), scopeName);
                CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.ERROR, request, e);
            }
        %>
        
        <script type="text/javascript">
            function forward() {
                location.href = "<%=forwardTo%>";
            }

            forward();
        </script>
    
    </div>
</div>
