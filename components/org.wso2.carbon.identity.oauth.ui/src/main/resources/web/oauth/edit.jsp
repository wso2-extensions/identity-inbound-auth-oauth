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

<%@ page import="java.util.ArrayList" %>
<%@ page import="java.util.Arrays" %>
<%@ page import="java.util.Collections" %>
<%@ page import="java.util.List" %>
<%@ page import="java.util.ResourceBundle" %>

<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib uri="http://wso2.org/projects/carbon/taglibs/carbontags.jar" prefix="carbon" %>

<script type="text/javascript" src="extensions/js/vui.js"></script>
<script type="text/javascript" src="../extensions/core/js/vui.js"></script>
<script type="text/javascript" src="../admin/js/main.js"></script>
<script type="text/javascript" src="../identity/validation/js/identity-validate.js"></script>

<jsp:include page="../dialog/display_messages.jsp"/>

<%

    String consumerkey = request.getParameter("consumerkey");
    String appName = request.getParameter("appName");

    OAuthConsumerAppDTO app = null;
    String forwardTo = null;
    String BUNDLE = "org.wso2.carbon.identity.oauth.ui.i18n.Resources";
    ResourceBundle resourceBundle = ResourceBundle.getBundle(BUNDLE, request.getLocale());
    String id = null;
    String secret = null;
    // grants
    boolean codeGrant = false;
    boolean implicitGrant = false;
    List<String> allowedGrants = null;
    String applicationSPName = null;
    OAuthAdminClient client = null;
    String action = null;
    String grants = null;
    String[] audiences = null;
    String audienceTableStyle = "display:none";
    List<String> allowedScopeValidators = new ArrayList<String>();
    List<String> scopeValidators = new ArrayList<String>();

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

        if (appName != null) {
            app = client.getOAuthApplicationDataByAppName(appName);
        } else {
            app = client.getOAuthApplicationData(consumerkey);
        }

        if (OAuthConstants.ACTION_REGENERATE.equalsIgnoreCase(action)) {
            String oauthAppState = client.getOauthApplicationState(consumerkey);
            client.regenerateSecretKey(consumerkey);
            if (OAuthConstants.OauthAppStates.APP_STATE_REVOKED.equalsIgnoreCase(oauthAppState)) {
                client.updateOauthApplicationState(consumerkey, OAuthConstants.OauthAppStates.APP_STATE_ACTIVE);
            }
            app.setOauthConsumerSecret(client.getOAuthApplicationData(consumerkey).getOauthConsumerSecret());
            CarbonUIMessage.sendCarbonUIMessage("Client Secret successfully updated for Client ID: " + consumerkey,
                    CarbonUIMessage.INFO, request);

        } else if (OAuthConstants.ACTION_REVOKE.equalsIgnoreCase(action)) {
            String oauthAppState = client.getOauthApplicationState(consumerkey);
            if (OAuthConstants.OauthAppStates.APP_STATE_REVOKED.equalsIgnoreCase(oauthAppState)) {
                CarbonUIMessage.sendCarbonUIMessage("Application is already revoked.",
                        CarbonUIMessage.INFO, request);
            } else {
                client.updateOauthApplicationState(consumerkey, OAuthConstants.OauthAppStates.APP_STATE_REVOKED);
                CarbonUIMessage.sendCarbonUIMessage("Application successfully revoked.", CarbonUIMessage.INFO, request);
            }
        } else {

            if (app.getCallbackUrl() == null) {
                app.setCallbackUrl("");
            }
            allowedGrants = new ArrayList<String>(Arrays.asList(client.getAllowedOAuthGrantTypes()));
            allowedScopeValidators = Arrays.asList(client.getAllowedScopeValidators());
            Collections.sort(allowedScopeValidators);
            if (OAuthConstants.OAuthVersions.VERSION_2.equals(app.getOAuthVersion())) {
                id = resourceBundle.getString("consumerkey.oauth20");
                secret = resourceBundle.getString("consumersecret.oauth20");
            } else {
                id = resourceBundle.getString("consumerkey.oauth10a");
                secret = resourceBundle.getString("consumersecret.oauth10a");
            }
            // setting grants if oauth version 2.0
            if (OAuthConstants.OAuthVersions.VERSION_2.equals(app.getOAuthVersion())) {
                grants = app.getGrantTypes();
                if (grants != null) {
                    codeGrant = grants.contains("authorization_code");
                    implicitGrant = grants.contains("implicit");
                } else {
                    grants = "";
                }
                audiences = app.getAudiences();
                String[] val = app.getScopeValidators();
                if (val != null) {
                    scopeValidators = Arrays.asList(val);
                }
            }
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
    if ((action != null) && ("revoke".equalsIgnoreCase(action) || "regenerate".equalsIgnoreCase(action))) {
        session.setAttribute("oauth-consum-secret", app.getOauthConsumerSecret());
%>
<script>
    location.href = '../application/configure-service-provider.jsp?action=<%=action%>&display=oauthapp&spName=<%=Encode.forUriComponent(applicationSPName)%>&oauthapp=<%=Encode.forUriComponent(app.getOauthConsumerKey())%>';
</script>
<% } else {
%>

<fmt:bundle basename="org.wso2.carbon.identity.oauth.ui.i18n.Resources">
    <carbon:breadcrumb label="app.settings"
                       resourceBundle="org.wso2.carbon.identity.oauth.ui.i18n.Resources"
                       topPage="false" request="<%=request%>"/>

    <script type="text/javascript" src="../carbon/admin/js/breadcrumbs.js"></script>
    <script type="text/javascript" src="../carbon/admin/js/cookies.js"></script>
    <script type="text/javascript" src="../carbon/admin/js/main.js"></script>

    <div id="middle">

        <h2><fmt:message key='view.application'/></h2>

        <div id="workArea">
            <script type="text/javascript">

                var audienceArr = [];

                function onClickUpdate() {
                    var versionValue = document.getElementsByName("oauthVersion")[0].value;
                    var callbackUrl = document.getElementsByName("callback")[0].value;
                    if (!(versionValue == '<%=OAuthConstants.OAuthVersions.VERSION_2%>')) {
                        if (callbackUrl.trim() == '') {
                            CARBON.showWarningDialog('<fmt:message key="callback.is.required"/>');
                            return false;
                        } else {
                            validate();
                        }
                    }

                    if ($(jQuery("#grant_authorization_code"))[0].checked || $(jQuery("#grant_implicit"))[0].checked) {
                        callbackUrl = document.getElementById('callback').value;
                        if (callbackUrl.trim() == '') {
                            CARBON.showWarningDialog('<fmt:message key="callback.is.required"/>');
                            return false;
                        } else {
                            validate();
                        }
                    } else {
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
                    var value = document.getElementsByName("application")[0].value;
                    if (value == '') {
                        CARBON.showWarningDialog('<fmt:message key="application.is.required"/>');
                        return false;
                    }
                    var versionValue = document.getElementsByName("oauthVersion")[0].value;
                    if (versionValue == '<%=OAuthConstants.OAuthVersions.VERSION_2%>') {
                        if (!$(jQuery("#grant_authorization_code"))[0].checked && !$(jQuery("#grant_implicit"))[0].checked) {
                            document.getElementsByName("callback")[0].value = '';
                        } else {
                            // This is to support providing regex patterns for callback URLs
                            if (callbackUrl.startsWith("regexp=")) {
                                // skip validation
                            } else if (!isWhiteListed(callbackUrl, ["url"])) {
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
                    document.editAppform.submit();
                }

                function adjustForm() {
                    var oauthVersion = $('input[name=oauthVersion]:checked').val();
                    var supportGrantCode = $('input[name=grant_authorization_code]:checked').val() != null;
                    var supportImplicit = $('input[name=grant_implicit]:checked').val() != null;

                    if (!supportGrantCode && !supportImplicit) {
                        $(jQuery('#callback_row')).hide();
                    } else {
                        $(jQuery('#callback_row')).show();
                    }
                    if (supportGrantCode) {
                        $(jQuery("#pkce_enable").show());
                        $(jQuery("#pkce_support_plain").show());
                    } else {
                        $(jQuery("#pkce_enable").hide());
                        $(jQuery("#pkce_support_plain").hide());
                    }

                }

                function toggleAudienceRestriction(chkbx) {
                    document.editAppform.audience.disabled = !chkbx.checked;
                    document.editAppform.addAudience.disabled = (!chkbx.checked);
                }

                function addAudienceFunc() {
                    var audience = $.trim(document.getElementById('audience').value);
                    if (audience === "") {
                        document.getElementById("audience").value = "";
                        return false;
                    }

                    if ($.inArray(audience, audienceArr) !== -1) {
                        CARBON.showWarningDialog('<fmt:message key="duplicate.audience.value"/>');
                        document.getElementById("audience").value = "";
                        return false;
                    }
                    audienceArr.push(audience);
                    var propertyCount = document.getElementById("audiencePropertyCounter");

                    var i = propertyCount.value;
                    var currentCount = parseInt(i);

                    currentCount = currentCount + 1;
                    propertyCount.value = currentCount;

                    document.getElementById('audienceTableId').style.display = '';
                    var audienceTableTBody = document.getElementById('audienceTableTbody');

                    var audienceRow = document.createElement('tr');
                    audienceRow.setAttribute('id', 'audienceRow' + i);

                    var audience = document.getElementById('audience').value;
                    var audiencePropertyTD = document.createElement('td');
                    audiencePropertyTD.setAttribute('style', 'padding-left: 40px ! important; color: rgb(119, 119, 119); font-style: italic;');
                    audiencePropertyTD.innerHTML = "" + audience + "<input type='hidden' name='audiencePropertyName' id='audiencePropertyName" + i + "'  value='" + audience + "'/> ";

                    var audienceRemoveTD = document.createElement('td');
                    audienceRemoveTD.innerHTML = "<a href='#' class='icon-link' style='background-image: url(../admin/images/delete.gif)' onclick='removeAudience(" + i + ");return false;'>" + "Delete" + "</a>";

                    audienceRow.appendChild(audiencePropertyTD);
                    audienceRow.appendChild(audienceRemoveTD);

                    audienceTableTBody.appendChild(audienceRow);
                    document.getElementById("audience").value = "";
                    return true;
                }

                function removeAudience(i) {
                    var propRow = document.getElementById("audienceRow" + i);
                    if (propRow !== undefined && propRow !== null) {
                        var parentTBody = propRow.parentNode;
                        if (parentTBody !== undefined && parentTBody !== null) {
                            parentTBody.removeChild(propRow);
                            if (!isContainRaw(parentTBody)) {
                                var propertyTable = document.getElementById("audienceTableId");
                                propertyTable.style.display = "none";
                            }
                        }
                    }
                }

                function isContainRaw(tbody) {
                    if (tbody.childNodes === null || tbody.childNodes.length === 0) {
                        return false;
                    } else {
                        for (var i = 0; i < tbody.childNodes.length; i++) {
                            var child = tbody.childNodes[i];
                            if (child !== undefined && child !== null) {
                                if (child.nodeName === "tr" || child.nodeName === "TR") {
                                    return true;
                                }
                            }
                        }
                    }
                    return false;
                }

                jQuery(document).ready(function () {
                    //on load adjust the form based on the current settings
                    adjustForm();
                    $("form[name='editAppform']").change(adjustForm);
                })
            </script>

            <form method="post" name="editAppform" action="edit-finish-ajaxprocessor.jsp" target="_self">
                <input id="consumerkey" name="consumerkey" type="hidden"
                       value="<%=Encode.forHtmlAttribute(app.getOauthConsumerKey())%>"/>
                <input id="consumersecret" name="consumersecret" type="hidden"
                       value="<%=Encode.forHtmlAttribute(app.getOauthConsumerSecret())%>"/>
                <table style="width: 100%" class="styledLeft">
                    <thead>
                    <tr>
                        <th><fmt:message key='app.settings'/></th>
                    </tr>
                    </thead>
                    <tbody>
                    <tr>
                        <td class="formRow">
                            <table class="normal" cellspacing="0">
                                <tr>
                                    <td class="leftCol-med"><fmt:message key='oauth.version'/></td>
                                    <td><%=Encode.forHtml(app.getOAuthVersion())%><input id="oauthVersion"
                                                                                         name="oauthVersion"
                                                                                         type="hidden"
                                                                                         value="<%=Encode.forHtmlAttribute(app.getOAuthVersion())%>"/>
                                    </td>
                                </tr>
                                <%if (applicationSPName == null) { %>
                                <tr>
                                    <td class="leftCol-med"><fmt:message key='application.name'/><span class="required">*</span>
                                    </td>
                                    <td><input class="text-box-big" id="application" name="application"
                                               type="text"
                                               value="<%=Encode.forHtmlAttribute(app.getApplicationName())%>"/></td>
                                </tr>
                                <%} else { %>
                                <tr style="display: none;">
                                    <td colspan="2" style="display: none;"><input class="text-box-big" id="application"
                                                                                  name="application"
                                                                                  type="hidden"
                                                                                  value="<%=Encode.forHtmlAttribute(applicationSPName)%>"/>
                                    </td>
                                </tr>
                                <%} %>
                                <tr id="callback_row">
                                    <td class="leftCol-med"><fmt:message key='callback'/><span class="required">*</span>
                                    </td>
                                    <td><input class="text-box-big" id="callback" name="callback"
                                               type="text" value="<%=Encode.forHtmlAttribute(app.getCallbackUrl())%>"/>
                                    </td>
                                </tr>

                                <script>
                                    if (<%=app.getOAuthVersion().equals(OAuthConstants.OAuthVersions.VERSION_1A)%> || <%=codeGrant%> || <%=implicitGrant%>) {
                                        $(jQuery('#callback_row')).attr('style', '');
                                    } else {
                                        $(jQuery('#callback_row')).attr('style', 'display:none');
                                    }
                                </script>
                                <% if (app.getOAuthVersion().equals(OAuthConstants.OAuthVersions.VERSION_2)) { %>
                                <tr id="grant_row" name="grant_row">
                                    <td class="leftCol-med"><fmt:message key='grantTypes'/></td>
                                    <td>
                                        <table>
                                            <%
                                                try {
                                                    if (allowedGrants.contains("authorization_code")) {
                                                        allowedGrants.remove("authorization_code");
                                            %>
                                            <tr>
                                                <td><label><input type="checkbox" id="grant_authorization_code"
                                                                  name="grant_authorization_code"
                                                                  value="authorization_code" <%=(grants.contains("authorization_code") ? "checked=\"checked\"" : "")%>
                                                                  onclick="toggleCallback()"/>Code</label></td>
                                            </tr>
                                            <%
                                                }
                                                if (allowedGrants.contains("implicit")) {
                                                    allowedGrants.remove("implicit");
                                            %>
                                            <tr>
                                                <td><label><input type="checkbox" id="grant_implicit"
                                                                  name="grant_implicit"
                                                                  value="implicit" <%=(grants.contains("implicit") ? "checked=\"checked\"" : "")%>
                                                                  onclick="toggleCallback()"/>Implicit</label></td>
                                            </tr>
                                            <%
                                                }
                                                if (allowedGrants.contains("password")) {
                                                    allowedGrants.remove("password");
                                            %>
                                            <tr>
                                                <td>
                                                    <lable><input type="checkbox" id="grant_password"
                                                                  name="grant_password"
                                                                  value="password" <%=(grants.contains("password") ? "checked=\"checked\"" : "")%>/>Password
                                                    </lable>
                                                </td>
                                            </tr>
                                            <%
                                                }
                                                if (allowedGrants.contains("client_credentials")) {
                                                    allowedGrants.remove("client_credentials");
                                            %>
                                            <tr>
                                                <td><label><input type="checkbox" id="grant_client_credentials"
                                                                  name="grant_client_credentials"
                                                                  value="client_credentials" <%=(grants.contains("client_credentials") ? "checked=\"checked\"" : "")%>/>Client
                                                    Credential</label></td>
                                            </tr>
                                            <%
                                                }
                                                if (allowedGrants.contains("refresh_token")) {
                                                    allowedGrants.remove("refresh_token");
                                            %>
                                            <tr>
                                                <td><label><input type="checkbox" id="grant_refresh_token"
                                                                  name="grant_refresh_token"
                                                                  value="refresh_token" <%=(grants.contains("refresh_token") ? "checked=\"checked\"" : "")%>/>Refresh
                                                    Token</label></td>
                                            </tr>
                                            <%
                                                }
                                                for (String grantType : allowedGrants) {
                                                    if (grantType.equals("urn:ietf:params:oauth:grant-type:saml1-bearer")) {
                                            %>
                                            <tr>
                                                <td><label><input type="checkbox"
                                                                  id="grant_urn:ietf:params:oauth:grant-type:saml1-bearer"
                                                                  name="grant_urn:ietf:params:oauth:grant-type:saml1-bearer"
                                                                  value="urn:ietf:params:oauth:grant-type:saml1-bearer" <%=(grants.contains(grantType) ? "checked=\"checked\"" : "")%>/>SAML1</label>
                                                </td>
                                            </tr>
                                            <%
                                            } else if (grantType.equals("urn:ietf:params:oauth:grant-type:saml2-bearer")) {
                                            %>
                                            <tr>
                                                <td><label><input type="checkbox"
                                                                  id="grant_urn:ietf:params:oauth:grant-type:saml2-bearer"
                                                                  name="grant_urn:ietf:params:oauth:grant-type:saml2-bearer"
                                                                  value="urn:ietf:params:oauth:grant-type:saml2-bearer" <%=(grants.contains(grantType) ? "checked=\"checked\"" : "")%>/>SAML2</label>
                                                </td>
                                            </tr>
                                            <%
                                            } else if (grantType.equals("iwa:ntlm")) {
                                            %>
                                            <tr>
                                                <td><label><input type="checkbox" id="grant_iwa:ntlm"
                                                                  name="grant_iwa:ntlm"
                                                                  value="iwa:ntlm" <%=(grants.contains(grantType) ? "checked=\"checked\"" : "")%>/>IWA-NTLM</label>
                                                </td>
                                            </tr>
                                            <%
                                            } else {
                                            %>
                                            <tr>
                                                <td><label><input type="checkbox"
                                                                  id=<%="grant_"+grantType%> name=<%="grant_" + grantType%>
                                                                  value=<%=grantType%> <%=(grants.contains(grantType) ? "checked=\"checked\"" : "")%>/><%=grantType%>
                                                </label></td>
                                            </tr>
                                            <%
                                                    }
                                                }
                                            } catch (Exception e) {
                                                forwardTo = "../admin/error.jsp";
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
                                <% if (client.isPKCESupportedEnabled()) {%>
                                <tr id="pkce_enable">
                                    <td class="leftCol-med">
                                        <fmt:message key='pkce.mandatory'/>
                                    </td>
                                    <td>
                                        <input type="checkbox" name="pkce"
                                               value="mandatory" <%=(app.getPkceMandatory() ? "checked" : "")%>  />Mandatory
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
                                        <input type="checkbox" name="pkce_plain"
                                               value="yes" <%=(app.getPkceSupportPlain() ? "checked" : "")%>>Yes
                                        <div class="sectionHelp">
                                            <fmt:message key='pkce.support.plain.hint'/>
                                        </div>
                                    </td>
                                </tr>
                                <% } %>
                                <% } %>

                                <tr>
                                    <td class="leftCol-med"><fmt:message key='user.access.token.expiry.time'/></td>
                                    <td><input id="userAccessTokenExpiryTime" name="userAccessTokenExpiryTime"
                                               type="text"
                                               value="<%=Encode.forHtmlAttribute(Long.toString(app.getUserAccessTokenExpiryTime()))%>"/>
                                        <fmt:message key='seconds'/>
                                    </td>
                                </tr>
                                <tr>
                                    <td class="leftCol-med"><fmt:message
                                            key='application.access.token.expiry.time'/></td>
                                    <td>
                                        <input id="applicationAccessTokenExpiryTime"
                                               name="applicationAccessTokenExpiryTime" type="text"
                                               value="<%=Encode.forHtmlAttribute(Long.toString(app.getApplicationAccessTokenExpiryTime()))%>"/>
                                        <fmt:message key='seconds'/>
                                    </td>
                                </tr>
                                <tr>
                                    <td class="leftCol-med"><fmt:message key='refresh.token.expiry.time'/></td>
                                    <td>
                                        <input id="refreshTokenExpiryTime" name="refreshTokenExpiryTime" type="text"
                                               value="<%=Encode.forHtmlAttribute(Long.toString(app.getRefreshTokenExpiryTime()))%>"/>
                                        <fmt:message key='seconds'/>
                                    </td>
                                </tr>
                                <!-- EnableAudienceRestriction -->
                                <%
                                    audienceTableStyle = app.getAudiences() != null ? "" :
                                            "display:none";
                                    if (OAuthUIUtil.isAudienceNotEmpty(app.getAudiences())) {
                                %>
                                <tr id="audience-enable">
                                    <td title="Enable Audience Restriction to restrict the audience. You may add audience members using the Audience text box and clicking the Add button"
                                        colspan="2"><input type="checkbox"
                                                           name="enableAudienceRestriction"
                                                           id="enableAudienceRestriction"
                                                           value="true" checked="checked"
                                                           onclick="toggleAudienceRestriction(this);"/>
                                        <fmt:message key="enable.audience.restriction"/>
                                    </td>
                                </tr>
                                <tr id="audience-add">
                                    <td style="padding-left: 40px ! important; color: rgb(119, 119, 119); font-style: italic;">
                                        <fmt:message key="sp.audience"/>
                                    </td>
                                    <td>
                                        <input type="text" id="audience" name="audience"
                                               class="text-box-big"/>
                                        <input id="addAudience" name="addAudience"
                                               type="button"
                                               value="<fmt:message key="oauth.add.audience"/>"
                                               onclick="return addAudienceFunc()"/>
                                    </td>
                                </tr>
                                <% } else {%>
                                <tr id="audience-enable">
                                    <td colspan="2"
                                        title="Enable Audience Restriction to restrict the audience. You may add audience members using the Audience text box and clicking the Add button">
                                        <input type="checkbox"
                                               name="enableAudienceRestriction"
                                               id="enableAudienceRestriction"
                                               value="true"
                                               onclick="toggleAudienceRestriction(this);"/>
                                        <fmt:message key="enable.audience.restriction"/>
                                    </td>
                                </tr>
                                <tr id="audience-add">
                                    <td style="padding-left: 40px ! important; color: rgb(119, 119, 119); font-style: italic;">
                                        <fmt:message key="sp.audience"/>
                                    </td>
                                    <td>
                                        <input type="text" id="audience" name="audience"
                                               class="text-box-big" disabled="disabled"/>
                                        <input id="addAudience" name="addAudience"
                                               type="button"
                                               disabled="disabled" value="<fmt:message key="oauth.add.audience"/>"
                                               onclick="return addAudienceFunc()"/>
                                    </td>
                                </tr>
                                <%} %>
                                <tr id="audience-table">
                                    <td></td>
                                    <td>
                                        <table id="audienceTableId"
                                               style="width: 40%; <%=audienceTableStyle%>"
                                               class="styledInner">
                                            <tbody id="audienceTableTbody">
                                            <%
                                                int j = 0;
                                                if (app.getAudiences() != null) {

                                            %>
                                            <%
                                                for (String audience : audiences) {
                                                    if (audience != null &&
                                                            !"null".equals(audience)) {
                                            %>
                                            <tr id="audienceRow<%=j%>">
                                                <td style="padding-left: 40px ! important; color: rgb(119, 119, 119); font-style: italic;">
                                                    <input type="hidden"
                                                           name="audiencePropertyName"
                                                           id="audiencePropertyName<%=j%>"
                                                           value="<%=Encode.forHtmlAttribute(audience)%>"/>
                                                    <%=Encode.forHtml(audience)%>
                                                </td>
                                                <td>
                                                    <a onclick="removeAudience('<%=j%>');return false;"
                                                       href="#" class="icon-link"
                                                       style="background-image: url(../admin/images/delete.gif)">Delete
                                                    </a>
                                                </td>
                                            </tr>
                                            <%
                                                        j++;
                                                    }
                                                }
                                            %>
                                            <%
                                                }
                                            %>
                                            <input type="hidden"
                                                   name="audiencePropertyCounter"
                                                   id="audiencePropertyCounter"
                                                   value="<%=j%>"/>
                                            </tbody>
                                        </table>
                                    </td>
                                </tr>
                                <!-- OIDC related properties -->
                                <tr id="validate_request_object_signature">
                                    <td colspan="2"
                                        title="Validate the signature of the request object">
                                        <input type="checkbox"
                                               name="validateRequestObjectSignature"
                                               id="validateRequestObjectSignature"
                                               value="true"
                                                <%=(app.getRequestObjectSignatureValidationEnabled() ? "checked" : "")%>
                                        />
                                        <fmt:message key='enable.request.object.signature.validation'/>
                                    </td>
                                </tr>

                                <tr id="encrypt_id_token">
                                    <td colspan="2"
                                        title="Encrypt the id_token">
                                        <input type="checkbox"
                                               name="encryptIdToken"
                                               id="encryptIdToken"
                                               value="true"
                                                <%=(app.getIdTokenEncryptionEnabled() ? "checked" : "")%>
                                        />
                                        <fmt:message key='enable.id.token.encryption'/>
                                    </td>
                                </tr>
                                    <%--Scope validators--%>
                                <tr id="scope_validator_row" name="scope_validator_row">
                                    <td class="leftCol-med"><fmt:message key='scopeValidators'/></td>
                                    <td>
                                        <table>
                                            <%
                                                for (String scopeValidator : allowedScopeValidators) {
                                            %>
                                            <tr>
                                                <td><label><input type="checkbox"
                                                                  id=<%="scope_validator_" + scopeValidator%> name=<%="scope_validator_" + scopeValidator%>
                                                                  value=<%=scopeValidator%> <%=(scopeValidators.contains(scopeValidator) ? "checked=\"checked\"" : "")%>/><%=scopeValidator%>
                                                </label></td>
                                            </tr>
                                            <%
                                                }
                                            %>
                                        </table>
                                    </td>
                                </tr>

                            </table>
                        </td>
                    </tr>
                    <tr>
                        <td class="buttonRow">
                            <input name="update"
                                   type="button" class="button" value="<fmt:message key='update'/>"
                                   onclick="onClickUpdate();"/>
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

<%
    }
%>
