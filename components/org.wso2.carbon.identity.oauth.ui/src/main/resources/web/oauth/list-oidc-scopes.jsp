<%--
  ~ Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
  --%>
<%@ page import="org.owasp.encoder.Encode" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIMessage" %>
<%@ page import="java.util.ResourceBundle" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIUtil" %>
<%@ page import="org.wso2.carbon.context.PrivilegedCarbonContext" %>
<%@ page import="org.wso2.carbon.identity.core.util.IdentityTenantUtil" %>
<%@ page import="org.apache.axis2.context.ConfigurationContext" %>
<%@ page import="org.wso2.carbon.CarbonConstants" %>
<%@ page import="org.wso2.carbon.utils.ServerConstants" %>
<%@ page import="org.wso2.carbon.identity.oauth.ui.client.OAuthAdminClient" %>

<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib uri="http://wso2.org/projects/carbon/taglibs/carbontags.jar"
           prefix="carbon" %>
<jsp:include page="../dialog/display_messages.jsp"/>

<fmt:bundle
        basename="org.wso2.carbon.identity.oauth.ui.i18n.Resources">
    <carbon:breadcrumb label="list.scope"
                       resourceBundle="org.wso2.carbon.identity.oauth.ui.i18n.Resources"
                       topPage="true" request="<%=request%>"/>
    <div id="middle">
        <h2><fmt:message key='title.list.scope'/></h2>
        <div id="workArea">
            
            <script type="text/javascript">

                function removeItem(sName) {
                    function doDelete() {
                        var scopeName = sName;
                        $.ajax({
                            type: 'POST',
                            url: 'remove-oidc-scope-finish-ajaxprocessor.jsp',
                            headers: {
                                Accept: "text/html"
                            },
                            data: 'scopeName=' + scopeName,
                            async: false,
                            success: function (responseText, status) {
                                if (status == "success") {
                                    location.assign("list-oidc-scopes.jsp");
                                }
                            }
                        });
                    }

                    CARBON.showConfirmationDialog('Are you sure you want to delete "' + sName +
                        '" scope information?',
                        doDelete, null);
                }
            </script>
            
            <%
                String[] scopes = null;
                String BUNDLE = "org.wso2.carbon.identity.oauth.ui.i18n.Resources";
                ResourceBundle resourceBundle = ResourceBundle.getBundle(BUNDLE, request.getLocale());
                
                try {
                    String serverURL = CarbonUIUtil.getServerURL(config.getServletContext(), session);
                    ConfigurationContext configContext = (ConfigurationContext)
                            config.getServletContext().getAttribute(CarbonConstants.CONFIGURATION_CONTEXT);
                    String cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_COOKIE);
                    OAuthAdminClient oAuthAdminClient = new OAuthAdminClient(cookie, serverURL, configContext);
                    scopes = oAuthAdminClient.getScopeNames();
                    
                } catch (Exception e) {
                    String message = resourceBundle.getString("error.while.listing.scopes");
                    CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.ERROR, request, e);
                }
            %>
            <table class="styledLeft" width="100%" id="ServiceProviders">
                <thead>
                <tr style="white-space: nowrap">
                    <th><fmt:message
                            key="scope.name"/></th>
                    <th style="width: 30%"><fmt:message
                            key="scope.action"/></th>
                </tr>
                </thead>
                <%
                    if (scopes != null && scopes.length > 0) {
                %>
                <tbody>
                <%
                    for (String scope : scopes) {
                        if (scope != null) {
                %>
                <tr>
                    <td><%=Encode.forHtml(scope)%>
                    </td>
                    
                    <td style="width: 100px; white-space: nowrap;"><a
                            title="Update OIDC Scope"
                            href="edit-oidc-claims.jsp?scopeName=<%=Encode.forUriComponent(scope)%>"
                            class="icon-link"
                            style="background-image: url(../admin/images/edit.gif)"><fmt:message
                            key='update'/></a>
                        
                        <a title="Delete OIDC Scope"
                           onclick="removeItem('<%=Encode.forJavaScriptAttribute(scope)%>');return
                                   false;" href="#"
                           class="icon-link"
                           style="background-image: url(../admin/images/delete.gif)"><fmt:message
                                key='delete'/>
                        </a>
                        
                        <a title="Add OIDC Claims for Scope"
                           href="add-oidc-claims.jsp?scopeName=<%=Encode.forUriComponent(scope)%>"
                           class="icon-link"
                           style="background-image: url(../admin/images/edit.gif)"><fmt:message
                                key='add.claims'/>
                        </a>
                    
                    </td>
                    
                </tr>
                <%
                        }
                    }
                %>
                </tbody>
                <% } else { %>
                <tbody>
                <tr>
                    <td colspan="3"><i><fmt:message key='no.scope.registered'/></i></td>
                </tr>
                </tbody>
                <% } %>
            </table>
        
        </div>
    </div>
</fmt:bundle>
