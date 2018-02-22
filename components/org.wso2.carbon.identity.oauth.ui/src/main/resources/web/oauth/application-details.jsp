<!--
~ Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

<%@ page import="org.owasp.encoder.Encode"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib prefix="carbon" uri="http://wso2.org/projects/carbon/taglibs/carbontags.jar"%>
<%@ page import="org.wso2.carbon.identity.application.mgt.ui.ApplicationBean" %>
<%@ page import="org.wso2.carbon.identity.application.mgt.ui.util.ApplicationMgtUIUtil" %>

<link href="css/idpmgt.css" rel="stylesheet" type="text/css" media="all"/>
<carbon:breadcrumb label="breadcrumb.oauth.application" resourceBundle="org.wso2.carbon.identity.oauth.ui.i18n.Resources"
                    topPage="true" request="<%=request%>" />
<jsp:include page="../dialog/display_messages.jsp"/>

<script type="text/javascript" src="../admin/js/main.js"></script>
<script type="text/javascript" src="../identity/validation/js/identity-validate.js"></script>

<%
ApplicationBean appBean = ApplicationMgtUIUtil.getApplicationBeanFromSession(session, request.getParameter("spName"));
if (appBean.getServiceProvider() == null || appBean.getServiceProvider().getApplicationName() == null) {
// if appbean is not set properly redirect the user to list-service-provider.jsp.
%>
<script>
location.href = "list-service-providers.jsp";
</script>
<%
	return;
}
    String spName = appBean.getServiceProvider().getApplicationName();
    String action = Encode.forJavaScript(request.getParameter("action"));
    boolean isNeedToUpdate = false;

    String attributeConsumingServiceIndex = request.getParameter("attrConServIndex");
	if (attributeConsumingServiceIndex != null){
		appBean.setAttributeConsumingServiceIndex(attributeConsumingServiceIndex);
	}

    String oauthapp = request.getParameter("oauthapp");
    if (oauthapp!=null && "update".equals(action)){
    	appBean.setOIDCAppName(oauthapp);
    	isNeedToUpdate = true;
    }

    String oauthConsumerSecret = null;
    if (session.getAttribute("oauth-consum-secret")!= null && ("update".equals(action) || "regenerate".equals(action))){
    	oauthConsumerSecret = (String) session.getAttribute("oauth-consum-secret");
    	appBean.setOauthConsumerSecret(oauthConsumerSecret);
    	session.removeAttribute("oauth-consum-secret");
    }

    oauthapp = appBean.getOIDCClientId();
%>

<script>
    function copyTextClick(value) {
      var copyText = value;
      copyText.select();
      document.execCommand("Copy");

      return false;
	}
</script>

<fmt:bundle basename="org.wso2.carbon.identity.oauth.ui.i18n.Resources">
    <div id="middle">
        <h2>
            <fmt:message key='title.oauth.application'/>
        </h2>
        <form id="configure-sp-form" method="post" name="configure-sp-form" method="post">
            <div id="workArea" style="margin-left:35px;margin-top:8px;">
                <div style="margin-top:35px;background-color: #f4f4f4; border-left: 6px solid #cccccc;height:50px;width:60%;">
                    <p style="margin: 25px 25px 25px 25px;padding-top:10px;display:block;"><strong>Note : <font color="red"><fmt:message key='note.oauth.application'/></font></strong></p>
                </div>
                <table style="margin-top:25px;">
                    <thead>
                        <tr style="height: 35px;">
                            <th class="leftCol-big" style="font-size: 15px;"><fmt:message key='consumerkey.oauth10a'/></th>
                            <td style="margin-left: 5px;">
                                <div>
                                    <input style="border: none; background: white; font-size: 14px;" size="25" autocomplete="off" id="oauthConsumerKey" name="oauthConsumerKey" value="<%=Encode.forHtmlContent(appBean.getOIDCClientId())%>"readonly="readonly">
                                    <span style="float: right;">
                                        <button onclick="return copyTextClick(document.getElementById('oauthConsumerKey'))" name="copyBtn" id="copyBtn"><fmt:message key='button.copy'/></button>
                                    </span>
                                </div>
                            </td>
                        </tr>
                        <tr style="height: 35px;">
                            <th class="leftCol-big" style="font-size: 15px;"><fmt:message key='consumersecret.oauth10a'/></th>
                            <td style="margin-left: 5px;">
                                <div>
                                    <input style="border: none; background: white;font-size: 14px;" size="25" autocomplete="off" id="oauthConsumerSecret" name="oauthConsumerSecret" value="<%=Encode.forHtmlAttribute(oauthConsumerSecret)%>"readonly="readonly">
                                    <span style="float: right;">
                                        <button onclick="return copyTextClick(document.getElementById('oauthConsumerSecret'))" name="copyBtn" id="copyBtn"><fmt:message key='button.copy'/></button>
                                    </span>
                                </div>
                            </td>
                        </tr>
                    </thead>
                </table>
            <% if ("update".equals(action)) { %>
                <input type="button" value="<fmt:message key='button.finish'/>" onclick="javascript:location.href='../application/configure-service-provider.jsp?action=update&display=oauthapp&spName=<%=Encode.forUriComponent(spName)%>&oauthapp=<%=Encode.forUriComponent(appBean.getOIDCClientId())%>'"/>
            <% } else { %>
                <input type="button" value="<fmt:message key='button.finish'/>" onclick="javascript:location.href='../application/configure-service-provider.jsp?display=oauthapp&spName=<%=Encode.forUriComponent(spName)%>&action=cancel'"/>
            <% } %>
            </div>
        </form>
    </div>
</fmt:bundle>
