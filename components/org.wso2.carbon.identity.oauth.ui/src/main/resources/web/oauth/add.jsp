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

<%@ page import="org.apache.axis2.context.ConfigurationContext" %>
<%@ page import="org.owasp.encoder.Encode" %>
<%@ page import="org.wso2.carbon.CarbonConstants" %>
<%@ page import="org.wso2.carbon.identity.oauth.common.OAuthConstants" %>
<%@ page import="org.wso2.carbon.identity.oauth.ui.client.OAuthAdminClient" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIMessage" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIUtil" %>
<%@ page import="org.wso2.carbon.utils.ServerConstants" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.util.Arrays" %>
<%@ page import="java.util.List" %>
<%@ page import="java.util.ResourceBundle" %>

<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib uri="http://wso2.org/projects/carbon/taglibs/carbontags.jar"  prefix="carbon" %>

<script type="text/javascript" src="extensions/js/vui.js"></script>
<script type="text/javascript" src="../extensions/core/js/vui.js"></script>
<script type="text/javascript" src="../admin/js/main.js"></script>
<script type="text/javascript" src="../identity/validation/js/identity-validate.js"></script>

<%
    String BUNDLE = "org.wso2.carbon.identity.oauth.ui.i18n.Resources";
    ResourceBundle resourceBundle = ResourceBundle.getBundle(BUNDLE, request.getLocale());
    String applicationSPName = request.getParameter("spName");
    session.setAttribute("application-sp-name", applicationSPName);

    OAuthAdminClient client = null;
%>

<jsp:include page="../dialog/display_messages.jsp"/>

<fmt:bundle
        basename="org.wso2.carbon.identity.oauth.ui.i18n.Resources">
    <carbon:breadcrumb label="add.new.application"
                       resourceBundle="org.wso2.carbon.identity.oauth.ui.i18n.Resources"
                       topPage="false" request="<%=request%>"/>

    <script type="text/javascript" src="../carbon/admin/js/breadcrumbs.js"></script>
    <script type="text/javascript" src="../carbon/admin/js/cookies.js"></script>
    <script type="text/javascript" src="../carbon/admin/js/main.js"></script>

    <div id="middle">
        <h2><fmt:message key='add.new.application'/></h2>

        <div id="workArea">
            <script type="text/javascript">
                function onClickAdd() {
                    var version2Checked = document.getElementById("oauthVersion20").checked;
                    if ($(jQuery("#grant_authorization_code"))[0].checked || $(jQuery("#grant_implicit"))[0].checked) {
                        var callbackUrl = document.getElementById('callback').value;
                        if (callbackUrl.trim() == '') {
                            CARBON.showWarningDialog('<fmt:message key="callback.is.required"/>');
                            return false;
                        } else {
                            validate();
                        }
                    } else {
                        var callbackUrl = document.getElementsByName("callback")[0].value;
                        if (!version2Checked) {
                            if (callbackUrl.trim() == '') {
                                CARBON.showWarningDialog('<fmt:message key="callback.is.required"/>');
                                return false;
                            }
                        }
                        validate();
                    }
                }

                function validate() {
                    var callbackUrl = document.getElementById('callback').value;
                    var userTokenExpiryTime = document.getElementById("userAccessTokenExpiryTime").value;
                    var applicationTokenExpiryTime = document.getElementById("userAccessTokenExpiryTime").value;
                    var refreshTokenExpiryTime = document.getElementById("refreshTokenExpiryTime").value;

                    if (callbackUrl.indexOf("#") !== -1) {
                        CARBON.showWarningDialog('<fmt:message key="callback.is.fragment"/>');
                        return false;
                    }
                    if ($(jQuery("#grant_authorization_code"))[0].checked || $(jQuery("#grant_implicit"))[0].checked) {
                        // This is to support providing regex patterns for callback URLs
                        if (callbackUrl.startsWith("regexp=")) {
                            // skip validation
                        } else if (!isWhiteListed(callbackUrl, ["url"])) {
                            CARBON.showWarningDialog('<fmt:message key="callback.is.not.url"/>');
                            return false;
                        }
                    }
                    var value = document.getElementsByName("application")[0].value;
                    if (value == '') {
                        CARBON.showWarningDialog('<fmt:message key="application.is.required"/>');
                        return false;
                    }
                    var version2Checked = document.getElementById("oauthVersion20").checked;
                    if (version2Checked) {
                        if (!$(jQuery("#grant_authorization_code"))[0].checked && !$(jQuery("#grant_implicit"))[0].checked) {
                            document.getElementsByName("callback")[0].value = '';
                        }
                        if (!isWhiteListed(userTokenExpiryTime, ["digits-only"])) {
                            CARBON.showWarningDialog('<fmt:message key="invalid.user.access.token.expiry.time"/>');
                            return false;
                        }
                        if (!isWhiteListed(applicationTokenExpiryTime, ["digits-only"])) {
                            CARBON.showWarningDialog('<fmt:message key="invalid.application.access.token.expiry.time"/>');
                            return false;
                        }
                        if (!isWhiteListed(refreshTokenExpiryTime, ["digits-only"])) {
                            CARBON.showWarningDialog('<fmt:message key="invalid.refresh.token.expiry.time"/>');
                            return false;
                        }
                    } else {
                        if (!isWhiteListed(callbackUrl, ["url"])) {
                            CARBON.showWarningDialog('<fmt:message key="callback.is.not.url"/>');
                            return false;

                        }
                        if (!isWhiteListed(userTokenExpiryTime, ["digits-only"])) {
                            CARBON.showWarningDialog('<fmt:message key="invalid.user.access.token.expiry.time"/>');
                            return false;
                        }
                        if (!isWhiteListed(applicationTokenExpiryTime, ["digits-only"])) {
                            CARBON.showWarningDialog('<fmt:message key="invalid.application.access.token.expiry.time"/>');
                            return false;
                        }
                        if (!isWhiteListed(refreshTokenExpiryTime, ["digits-only"])) {
                            CARBON.showWarningDialog('<fmt:message key="invalid.refresh.token.expiry.time"/>');
                            return false;
                        }
                    }
                    document.addAppform.submit();
                }
                function adjustForm() {
                    var oauthVersion = $('input[name=oauthVersion]:checked').val();
                    var supportGrantCode = $('input[name=grant_authorization_code]:checked').val() != null;
                    var supportImplicit = $('input[name=grant_implicit]:checked').val() != null;

                    if(oauthVersion == "<%=OAuthConstants.OAuthVersions.VERSION_1A%>") {
                        $(jQuery('#grant_row')).hide();
                        $(jQuery("#pkce_enable").hide());
                        $(jQuery("#pkce_support_plain").hide());
                        $(jQuery('#userAccessTokenPlain').hide());
                        $(jQuery('#applicationAccessTokenPlain').hide());
                        $(jQuery('#refreshTokenPlain').hide());
                    } else if(oauthVersion == "<%=OAuthConstants.OAuthVersions.VERSION_2%>") {
                        $(jQuery('#grant_row')).show();
                        $(jQuery("#pkce_enable").show());
                        $(jQuery("#pkce_support_plain").show());
                        $(jQuery('#userAccessTokenPlain').show());
                        $(jQuery('#applicationAccessTokenPlain').show());
                        $(jQuery('#refreshTokenPlain').show());

                        if(!supportGrantCode && !supportImplicit){
                            $(jQuery('#callback_row')).hide();
                        } else {
                            $(jQuery('#callback_row')).show();
                        }
                        if(supportGrantCode) {
                            $(jQuery("#pkce_enable").show());
                            $(jQuery("#pkce_support_plain").show());
                        } else {
                            $(jQuery("#pkce_enable").hide());
                            $(jQuery("#pkce_support_plain").hide());
                        }
                    }

                }
                jQuery(document).ready(function() {
                    //on load adjust the form based on the current settings
                    adjustForm();
                    $(jQuery("#addAppForm input")).change(adjustForm);
                })

            </script>

            <form id="addAppForm" method="post" name="addAppform" action="add-finish-ajaxprocessor.jsp"
                  target="_self">
                <table style="width: 100%" class="styledLeft">
                    <thead>
                    <tr>
                        <th><fmt:message key='new.app'/></th>
                    </tr>
                    </thead>
                    <tbody>
		    <tr>
			<td class="formRow">
				<table class="normal" >
                            <tr>
                                <td class="leftCol-med"><fmt:message key='oauth.version'/><span class="required">*</span> </td>
                                <td><input id="oauthVersion10a" name="oauthVersion" type="radio" value="<%=OAuthConstants.OAuthVersions.VERSION_1A%>" />1.0a
                                    <input id="oauthVersion20" name="oauthVersion" type="radio" value="<%=OAuthConstants.OAuthVersions.VERSION_2%>" CHECKED />2.0</td>
                            </tr>
                            <%if  (applicationSPName!= null) {%>
                             <tr style="display: none;">
		                        <td colspan="2" style="display: none;"><input class="text-box-big" type="hidden" id="application" name="application"
		                                   value="<%=Encode.forHtmlAttribute(applicationSPName)%>" /></td>
		                    </tr>
                            <% } else { %>
		                    <tr>
		                        <td class="leftCol-med"><fmt:message key='application.name'/><span class="required">*</span></td>
		                        <td><input class="text-box-big" id="application" name="application"
		                                   type="text" /></td>
		                    </tr>
		                    <% } %>
		                    <tr id="callback_row">
		                        <td class="leftCol-med"><fmt:message key='callback'/><span class="required">*</span></td>
                                <td><input class="text-box-big" id="callback" name="callback" type="text"
                                           white-list-patterns="https-url"/></td>
		                    </tr>
		                     <tr id="grant_row" name="grant_row">
		                        <td class="leftCol-med"><fmt:message key='grantTypes'/></td>
		                        <td>
		                        <table>
                                    <%
                                        String forwardTo = "index.jsp";
                                        try {
                                            String cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_COOKIE);
                                            String backendServerURL = CarbonUIUtil.getServerURL(config.getServletContext(), session);
                                            ConfigurationContext configContext =
                                                    (ConfigurationContext) config.getServletContext()
                                                            .getAttribute(CarbonConstants.CONFIGURATION_CONTEXT);
                                            client = new OAuthAdminClient(cookie, backendServerURL, configContext);
                                            List<String> allowedGrants = new ArrayList<String>(Arrays.asList(client.getAllowedOAuthGrantTypes()));
                                            if (allowedGrants.contains("authorization_code")) {
                                                allowedGrants.remove("authorization_code");
                                                %><tr><td><label><input type="checkbox" id="grant_authorization_code" name="grant_authorization_code" value="authorization_code" checked="checked" onclick="toggleCallback()"/>Code</label></td></tr><%
                                            }
                                            if (allowedGrants.contains("implicit")) {
                                                allowedGrants.remove("implicit");
                                                %><tr><td><label><input type="checkbox" id="grant_implicit" name="grant_implicit" value="implicit" checked="checked" onclick="toggleCallback()"/>Implicit</label></td></tr><%
                                            }
                                            if (allowedGrants.contains("password")) {
                                                allowedGrants.remove("password");
                                                %><tr><td><lable><input type="checkbox" id="grant_password" name="grant_password" value="password" checked="checked"/>Password</lable></td></tr><%
                                            }
                                            if (allowedGrants.contains("client_credentials")) {
                                                allowedGrants.remove("client_credentials");
                                                %><tr><td><label><input type="checkbox" id="grant_client_credentials" name="grant_client_credentials" value="client_credentials" checked="checked"/>Client Credential</label></td></tr><%
                                            }
                                            if (allowedGrants.contains("refresh_token")) {
                                                allowedGrants.remove("refresh_token");
                                                %><tr><td><label><input type="checkbox" id="grant_refresh_token" name="grant_refresh_token" value="refresh_token" checked="checked"/>Refresh Token</label></td></tr><%
                                            }

                                            for (String grantType : allowedGrants) {
                                                if (grantType.equals("urn:ietf:params:oauth:grant-type:saml1-bearer")) {
                                                    %><tr><td><label><input type="checkbox" id="grant_urn:ietf:params:oauth:grant-type:saml1-bearer" name="grant_urn:ietf:params:oauth:grant-type:saml1-bearer" value="urn:ietf:params:oauth:grant-type:saml1-bearer" checked="checked"/>SAML1</label></td></tr><%
                                                } else if (grantType.equals("urn:ietf:params:oauth:grant-type:saml2-bearer")) {
                                                    %><tr><td><label><input type="checkbox" id="grant_urn:ietf:params:oauth:grant-type:saml2-bearer" name="grant_urn:ietf:params:oauth:grant-type:saml2-bearer" value="urn:ietf:params:oauth:grant-type:saml2-bearer" checked="checked"/>SAML2</label></td></tr><%
                                                } else if (grantType.equals("iwa:ntlm")) {
                                                    %><tr><td><label><input type="checkbox" id="grant_iwa:ntlm" name="grant_iwa:ntlm" value="iwa:ntlm" checked="checked"/>IWA-NTLM</label></td></tr><%
                                                } else {
                                                    %><tr><td><label><input type="checkbox" id=<%="grant_"+grantType%> name=<%="grant_"+grantType%> value=<%=grantType%> checked="checked"/><%=grantType%></label></td></tr><%
                                                }

                                            }
                                        } catch (Exception e) {
                                            String message = resourceBundle.getString("error.while.getting.allowed.grants") + " : " + e.getMessage();
                                            CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.ERROR, request, e);
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

		                        </table>   
		                        </td>
		                    </tr>
                            <%if(client.isPKCESupportedEnabled()) {%>
                            <tr id="pkce_enable">
                                <td class="leftCol-med">
                                    <fmt:message key='pkce.mandatory'/>
                                </td>
                                <td>
                                    <input type="checkbox" name="pkce" value="mandatory"/>Mandatory
                                    <div class="sectionHelp">
                                        <fmt:message key='pkce.mandatory.hint'/>
                                    </div>
                                </td>
                            </tr>
                            <tr id="pkce_support_plain">
                                <td>
                                    <fmt:message key='pkce.support.plain'/>
                                </td>
                                <td>
                                    <input type="checkbox" name="pkce_plain" value="yes" checked>Yes
                                    <div class="sectionHelp">
                                        <fmt:message key='pkce.support.plain.hint'/>
                                    </div>
                                </td>
                            </tr>
                            <% } %>
                    <tr id="tb_enable">
                        <td class="leftCol-med">
                            <fmt:message key='tb.enable'/>
                        </td>
                        <td>
                            <input type="checkbox" name="tb" value="mandatory"/>Enable
                            <div class="sectionHelp">
                                <fmt:message key='tb.enable.hint'/>
                            </div>
                        </td>
                    </tr>
                        <tr id="userAccessTokenPlain">
                            <td class="leftCol-med"><fmt:message key='user.access.token.expiry.time'/></td>
                            <td><input id="userAccessTokenExpiryTime" name="userAccessTokenExpiryTime"
                                       type="text" value="<%=client.getOAuthTokenExpiryTimeDTO().getUserAccessTokenExpiryTime()%>" />
                                <fmt:message key='seconds'/>
                            </td>
                        </tr>
                        <tr id="applicationAccessTokenPlain">
                            <td class="leftCol-med"><fmt:message key='application.access.token.expiry.time'/></td>
                            <td>
                                <input id="applicationAccessTokenExpiryTime" name="applicationAccessTokenExpiryTime" type="text"
                                       value="<%=client.getOAuthTokenExpiryTimeDTO().getApplicationAccessTokenExpiryTime()%>" />
                                <fmt:message key='seconds'/>
                            </td>
                        </tr>
                        <tr id="refreshTokenPlain">
                            <td class="leftCol-med"><fmt:message key='refresh.token.expiry.time'/></td>
                            <td>
                                <input id="refreshTokenExpiryTime" name="refreshTokenExpiryTime" type="text" value="<%=client.getOAuthTokenExpiryTimeDTO().getRefreshTokenExpiryTime()%>" />
                                <fmt:message key='seconds'/>
                            </td>
                        </tr>
				</table>
			</td>
		    </tr>

                    <tr>
                        <td class="buttonRow" >
                            <input name="addprofile" type="button" class="button" value="<fmt:message key='add'/>" onclick="onClickAdd();"/>
                            
                            <%

                            boolean applicationComponentFound = CarbonUIUtil.isContextRegistered(config, "/application/");
                            if (applicationComponentFound) {                            
                            %>
                            <input type="button" class="button"
                                       onclick="javascript:location.href='../application/configure-service-provider.jsp?spName=<%=Encode.forUriComponent(applicationSPName)%>'"
                                   value="<fmt:message key='cancel'/>"/>
                            <% } else { %>
                                   
                            <input type="button" class="button"
                                       onclick="javascript:location.href='index.jsp?region=region1&item=oauth_menu&ordinal=0'"
                                   value="<fmt:message key='cancel'/>"/>
                            <%} %>
                       </td>
                    </tr>
                    </tbody>
                </table>

            </form>
        </div>
    </div>
</fmt:bundle>

