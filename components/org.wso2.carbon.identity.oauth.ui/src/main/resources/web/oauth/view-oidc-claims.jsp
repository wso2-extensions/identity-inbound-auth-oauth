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
<%@ page import="org.owasp.encoder.Encode" %>
<%@ page import="org.wso2.carbon.context.PrivilegedCarbonContext" %>
<%@ page import="org.wso2.carbon.identity.core.util.IdentityTenantUtil" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIUtil" %>
<%@ page import="org.apache.axis2.context.ConfigurationContext" %>
<%@ page import="org.wso2.carbon.CarbonConstants" %>
<%@ page import="org.wso2.carbon.utils.ServerConstants" %>
<%@ page import="org.wso2.carbon.identity.oauth.ui.client.OAuthAdminClient" %>
<%@ page import="static org.wso2.carbon.identity.oauth.ui.util.OAuthUIConstants.SCOPE_NAME" %>
<jsp:include page="../dialog/display_messages.jsp"/>

<%
    String scope = request.getParameter(SCOPE_NAME);
    String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
    int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
    String serverURL = CarbonUIUtil.getServerURL(config.getServletContext(), session);
    ConfigurationContext configContext = (ConfigurationContext)
            config.getServletContext().getAttribute(CarbonConstants.CONFIGURATION_CONTEXT);
    String cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_COOKIE);
    OAuthAdminClient oAuthAdminClient = new OAuthAdminClient(cookie, serverURL, configContext);
    String[] oidcClaims = oAuthAdminClient.loadAllOIDCClaims(tenantId, scope);

%>


<fmt:bundle
        basename="org.wso2.carbon.identity.oauth.ui.i18n.Resources">
    <carbon:breadcrumb label="oidc.claim.url"
                       resourceBundle="org.wso2.carbon.identity.oauth.ui.i18n.Resources"
                       topPage="true" request="<%=request%>"/>
    
    <div id="middle">
        <h2><fmt:message key="view.claims"/> <%=Encode.forHtml(scope)%>
        </h2>
        <div id="workArea">
            
            <script type="text/javascript">
                function doCancel() {
                    location.href = '<%=Encode.forJavaScriptBlock("list-oidc-scopes.jsp")%>';
                }
            </script>
            
            <table class="styledLeft" width="100%" id="oidcClaims">
                <thead>
                <tr style="white-space: nowrap">
                    <th class="leftCol-med"><fmt:message key="oidc.claim.url"/></th>
                </tr>
                </thead>
                <%
                    if (oidcClaims.length > 0) {
                %>
                <tbody>
                <%
                    for (String claim : oidcClaims) {
                %>
                <tr>
                    <td><%=Encode.forHtml(claim)%>
                    </td>
                </tr>
                <%
                    }
                %>
                </tbody>
                <% } else { %>
                <tbody>
                <tr>
                    <td colspan="3"><i><fmt:message key="no.claims.found"/></i></td>
                </tr>
                </tbody>
                <% } %>
            </table>
            <table class="styledLeft noBorders" style="margin-top: 10px">
                <tbody>
                <tr>
                    <td class="buttonRow">
                        <input class="button" type="button" value="<fmt:message key="back"/>" onclick="doCancel()"/>
                    </td>
                </tr>
                </tbody>
            </table>
        </div>
    </div>
</fmt:bundle>
