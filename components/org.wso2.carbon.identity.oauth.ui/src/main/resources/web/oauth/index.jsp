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
<%@ page import="org.wso2.carbon.identity.oauth.common.OAuthConstants" %>
<%@ page import="org.wso2.carbon.identity.oauth.stub.dto.OAuthConsumerAppDTO" %>
<%@ page import="org.wso2.carbon.identity.oauth.ui.client.OAuthAdminClient" %>
<%@ page import="org.wso2.carbon.identity.oauth.ui.util.OAuthUIUtil" %>
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
    OAuthConsumerAppDTO[] apps = null;
    String BUNDLE = "org.wso2.carbon.identity.oauth.ui.i18n.Resources";
    ResourceBundle resourceBundle = ResourceBundle.getBundle(BUNDLE, request.getLocale());
    String forwardTo = null;
    String addAction = "add.jsp";
    OAuthAdminClient client = null;
    
    int numberOfPages = 0;
    String isPaginatedString = request.getParameter("isPaginated");
    if (isPaginatedString != null && isPaginatedString.equals("true")) {
        client = (OAuthAdminClient) session.getAttribute(OAuthConstants.OAUTH_ADMIN_CLIENT);
        numberOfPages = (Integer) session.getAttribute(OAuthConstants.OAUTH_DATA_PAGE_COUNT);
    }
    String paginationValue = "isPaginated=true";
    
    String pageNumber = request.getParameter("pageNumber");
    if (pageNumber == null) {
        pageNumber = "0";
    }
    int pageNumberInt = 0;
    try {
        pageNumberInt = Integer.parseInt(pageNumber);
    } catch (NumberFormatException ignored) {
    }
    
    try {
        String cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_COOKIE);
        String backendServerURL = CarbonUIUtil.getServerURL(config.getServletContext(), session);
        ConfigurationContext configContext =
                (ConfigurationContext) config.getServletContext().getAttribute(CarbonConstants.CONFIGURATION_CONTEXT);
        if (client == null) {
            int itemsPerPageInt = OAuthConstants.DEFAULT_ITEMS_PER_PAGE;
            client = new OAuthAdminClient(cookie, backendServerURL, configContext);
            if (client.getAllOAuthApplicationData() != null) {
                numberOfPages = (int) Math.ceil((double) client.getAllOAuthApplicationData().length / itemsPerPageInt);
                session.setAttribute(OAuthConstants.OAUTH_ADMIN_CLIENT, client);
                session.setAttribute(OAuthConstants.OAUTH_DATA_PAGE_COUNT, numberOfPages);
            }
        }
        if (client != null && client.getAllOAuthApplicationData() != null) {
            apps = OAuthUIUtil.doPaging(pageNumberInt, client.getAllOAuthApplicationData());
        }
        
    } catch (Exception e) {
        String message = resourceBundle.getString("error.while.loading.user.application.data");
        CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.ERROR, request);
        forwardTo = "../admin/error.jsp";
%>

<script type="text/javascript">
    function forward() {
        location.href = "<%=forwardTo%>";
    }
</script>

<script type="text/javascript">
    forward();
</script>
<%
    }
%>

<fmt:bundle basename="org.wso2.carbon.identity.oauth.ui.i18n.Resources">
    <carbon:breadcrumb
            label="identity.oauth"
            resourceBundle="org.wso2.carbon.identity.oauth.ui.i18n.Resources"
            topPage="true"
            request="<%=request%>"/>
    
    <script type="text/javascript" src="../carbon/admin/js/breadcrumbs.js"></script>
    <script type="text/javascript" src="../carbon/admin/js/cookies.js"></script>
    <script type="text/javascript" src="../carbon/admin/js/main.js"></script>
    
    <div id="middle">
        
        <h2><fmt:message key='oauth.management'/></h2>
        
        <div id="workArea">
            <script type="text/javascript">
                function itemRemove(consumerkey, appname) {

                    function doDelete() {
                        $.ajax({
                            type: 'POST',
                            url: 'remove-app-ajaxprocessor.jsp',
                            headers: {
                                Accept: "text/html"
                            },
                            data: 'consumerkey=' + consumerkey,
                            async: false,
                            success: function (responseText, status) {
                                if (status == "success") {
                                    location.assign("index.jsp");
                                }
                            }
                        });
                    }

                    CARBON.showConfirmationDialog('<fmt:message key='remove.message1'/>' + appname + '<fmt:message key='remove.message2'/>',
                        doDelete, null);
                }
            </script>
            
            <div style="height:30px;">
                <a href="javascript:document.location.href='<%=addAction%>'" class="icon-link"
                   style="background-image:url(../admin/images/add.gif);"><fmt:message
                        key='add.new.application'/></a>
            </div>
            
            <table style="width: 100%" class="styledLeft">
                <thead>
                <tr>
                    <th colspan="2"><fmt:message key='available.applications'/></th>
                </tr>
                </thead>
                <tbody>
                <%
                    if (apps != null && apps.length > 0) {
                        for (int i = 0; i < apps.length; i++) {
                            if (apps[i] != null) {
                %>
                <tr>
                    <td width="50%"><a
                            href="edit.jsp?consumerkey=<%=Encode.forUriComponent(apps[i].getOauthConsumerKey())%>"><%=Encode
                            .forHtml(apps[i].getApplicationName())%>
                    </a></td>
                    <td width="50%"><a title="<fmt:message key='remove.app'/>"
                                       onclick="itemRemove('<%=Encode.forJavaScriptAttribute(apps[i].getOauthConsumerKey())%>','<%=Encode.forJavaScriptAttribute(apps[i].getApplicationName())%>');return false;"
                                       href="#"
                                       style="background-image: url(../oauth/images/delete.gif);"
                                       class="icon-link">
                        <fmt:message key='delete'/></a></td>
                </tr>
                <%
                        }
                    }
                } else {
                %>
                <tr>
                    <td width="100%" colspan="2"><i><fmt:message key='no.apps'/></i></td>
                </tr>
                <%
                    }
                %>
                </tbody>
            </table>
            <carbon:paginator pageNumber="<%=pageNumberInt%>"
                              numberOfPages="<%=numberOfPages%>"
                              page="index.jsp"
                              pageNumberParameterName="pageNumber"
                              parameters="<%=Encode.forHtmlAttribute(paginationValue)%>"
                              resourceBundle="org.wso2.carbon.identity.oauth.ui.i18n.Resources"
                              prevKey="prev" nextKey="next"/>
        
        </div>
    </div>
</fmt:bundle>
