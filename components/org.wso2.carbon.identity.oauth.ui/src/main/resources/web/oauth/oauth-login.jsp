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

<%@ page import="org.owasp.encoder.Encode" %>
<%@ page import="java.net.URLDecoder" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib uri="http://wso2.org/projects/carbon/taglibs/carbontags.jar" prefix="carbon" %>

<%
    String cssLocation = request.getParameter("css");
    if ("null".equals(cssLocation)) {
        cssLocation = null;
    }
    
    if (cssLocation != null) {
        cssLocation = URLDecoder.decode(cssLocation, "UTF-8");
    }
    
    String forwardPage = request.getParameter("forwardPage");
    if (forwardPage != null) {
        forwardPage = URLDecoder.decode(forwardPage, "UTF-8");
        session.setAttribute("forwardPage", forwardPage);
    }
%>

<%
    if (cssLocation != null) {
        // This request is coming from a non-admin console
%>
<html xmlns="http://www.w3.org/1999/xhtml">

<head>
    <meta http-equiv="content-type" content="text/html;charset=utf-8"/>
    <title>OAuth Login</title>
    
    <link href="../admin/css/global.css" rel="stylesheet" type="text/css" media="all"/>
    <link href="../dialog/css/jqueryui/jqueryui-themeroller.css" rel="stylesheet" type="text/css"
          media="all"/>
    <link href="../dialog/css/dialog.css" rel="stylesheet" type="text/css" media="all"/>
    
    <link href="<%=Encode.forUriComponent(cssLocation)%>" rel="stylesheet" type="text/css"
          media="all"/>
    
    <link rel="icon" href="../admin/images/favicon.ico" type="image/x-icon"/>
    <link rel="shortcut icon" href="../admin/images/favicon.ico" type="image/x-icon"/>
    
    <script type="text/javascript" src="../admin/js/jquery.js"></script>
    
    <script type="text/javascript" src="../admin/js/jquery.form.js"></script>
    <script type="text/javascript" src="../dialog/js/jqueryui/jquery-ui.min.js"></script>
    <script type="text/javascript" src="../admin/js/main.js"></script>
    
    <script type="text/javascript" src="../admin/js/WSRequest.js"></script>
    <script type="text/javascript" src="../admin/js/cookies.js"></script>
</head>

<body>
<div id="dcontainer"></div>
<script type="text/javascript" src="../dialog/js/dialog.js"></script>

<!--This is the link panel of the portal page-->
<div id="link-panel">
    <div class="left-logo">
        <a class="header-home" href="../../portal">
            <img width="179" height="28" src="images/1px.gif"/>
        </a>
    </div>
</div>
<div id="dcontainer"></div>
<script type="text/javascript" src="../dialog/js/dialog.js"></script>
<%

} else {
%>
<jsp:include page="../dialog/display_messages.jsp"/>
<%
    }
%>

<link media="all" type="text/css" rel="stylesheet" href="css/registration.css"/>
<fmt:bundle basename="org.wso2.carbon.identity.oauth.ui.i18n.Resources">
    
    <script type="text/javascript" src="../carbon/admin/js/breadcrumbs.js"></script>
    <script type="text/javascript" src="../carbon/admin/js/cookies.js"></script>
    <script type="text/javascript" src="../carbon/admin/js/main.js"></script>
    
    
    <div id="middle">
        
        <h2><fmt:message key="oauth.login"/></h2>
        
        <div id="workArea">
            <table style="width:100%">
                <tr>
                    
                    <td style="width:50%">
                        <div id="loginbox" class="identity-box" style="height:160px;">
                            <script type="text/javascript">
                                function validate() {
                                    var username = document.getElementsByName("oauth_user_name")[0].value;
                                    if (username == '') {
                                        CARBON.showWarningDialog('<fmt:message key="username.required"/>');
                                        return false;
                                    }
                                    var password = document.getElementsByName("oauth_user_password")[0].value;
                                    if (password == '') {
                                        CARBON.showWarningDialog('<fmt:message key="password.required"/>');
                                        return false;
                                    }

                                    document.oauthsign.submit();
                                }
                            </script>
                            
                            <table style="border:none !important;width: 100%" class="styledLeft">
                                
                                <tr>
                                    <td><b><%=Encode.forHtml((String) session.getAttribute("oauth_app_name")) +
                                            " "%><fmt:message key='oauth.signin.message'/><%=Encode
                                            .forHtml((String) session.getAttribute("oauth_scope"))%>
                                    </b></td>
                                </tr>
                            
                            </table>
                            
                            <form method="post" name="oauthsign" action="oauth-login-finish-ajaxprocessor.jsp">
                                <%
                                    if (cssLocation != null) {
                                %>
                                <input type="hidden" name="forwardPage"
                                       value="<%=Encode.forHtmlAttribute(forwardPage)%>"/>
                                <input type="hidden" name="css"
                                       value="<%=Encode.forHtmlAttribute(cssLocation)%>"/>
                                <%
                                    }
                                %>
                                <table class="styledLeft noBorders" style="border:none !important;">
                                    <tr>
                                        <td class="leftCol-small"><fmt:message key='user.name'/></td>
                                        <td>
                                            <input class='text-box-big' id='oauth_user_name'
                                                   name="oauth_user_name" size='30'/>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td class="leftCol-small"><fmt:message key='password'/></td>
                                        <td>
                                            <input class='text-box-big' id='oauth_user_password'
                                                   name="oauth_user_password" size='30'
                                                   type="password" autocomplete="off"/>
                                        </td>
                                    </tr>
                                    <tr>
                                        
                                        <td class="buttonRow" colspan="2">
                                            <input name="adduser" type="button" class="button"
                                                   value="<fmt:message key='allow'/>"
                                                   onclick="validate();"/>
                                            <%
                                                String forwardUrl = "../../carbon/admin/index.jsp";
                                                if (forwardPage != null) {
                                                    forwardUrl = forwardPage;
                                                }
                                            %>
                                            <input type="button" class="button"
                                                   onclick="javascript:location.href='<%=forwardUrl%>'"
                                                   value="<fmt:message key='deny'/>"/>
                                        </td>
                                    </tr>
                                
                                </table>
                            </form>
                    </td>
                </tr>
            </table>
        
        </div>
    
    </div>
</fmt:bundle>
<%
    if (cssLocation != null) {
        // Closing HTML page tags.
%>
<div class="footer-content">
    <div class="copyright">&copy; 2008 - 2011 WSO2 Inc. All Rights Reserved.</div>
</div>
</body>
</html>
<%
    }
%>