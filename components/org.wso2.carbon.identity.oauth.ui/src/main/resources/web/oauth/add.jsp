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
<%@ page import="java.util.Collections" %>
<%@ page import="java.util.List" %>
<%@ page import="java.util.ResourceBundle" %>
<%@ page import="org.wso2.carbon.identity.oauth.ui.util.OAuthUIUtil" %>

<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib uri="http://wso2.org/projects/carbon/taglibs/carbontags.jar" prefix="carbon" %>

<script type="text/javascript" src="extensions/js/vui.js"></script>
<script type="text/javascript" src="../extensions/core/js/vui.js"></script>
<script type="text/javascript" src="../admin/js/main.js"></script>
<script type="text/javascript" src="../identity/validation/js/identity-validate.js"></script>

<%
    String forwardTo = "index.jsp";
    String BUNDLE = "org.wso2.carbon.identity.oauth.ui.i18n.Resources";
    String DEFAULT_TOKEN_TYPE = "default";
    ResourceBundle resourceBundle = ResourceBundle.getBundle(BUNDLE, request.getLocale());
    String applicationSPName = request.getParameter("spName");

    OAuthAdminClient client = null;
    String audienceTableStyle = "display:none";
    String cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_COOKIE);
    String backendServerURL = CarbonUIUtil.getServerURL(config.getServletContext(), session);
    ConfigurationContext configContext = (ConfigurationContext) config.getServletContext()
            .getAttribute(CarbonConstants.CONFIGURATION_CONTEXT);
    client = new OAuthAdminClient(cookie, backendServerURL, configContext);
    List<String> allowedGrants = new ArrayList<String>();
    List<String> scopeValidators = new ArrayList<String>();
    List<String> tokenTypes = new ArrayList<String>();

    String defaultIdTokenEncryptionAlgorithm = client.getSupportedIDTokenAlgorithms().getDefaultIdTokenEncryptionAlgorithm();
    String[] supportedIdTokenEncryptionAlgorithms =
            client.getSupportedIDTokenAlgorithms().getSupportedIdTokenEncryptionAlgorithms();
    String defaultIdTokenEncryptionMethod = client.getSupportedIDTokenAlgorithms().getDefaultIdTokenEncryptionMethod();
    String[] supportedIdTokenEncryptionMethods =
            client.getSupportedIDTokenAlgorithms().getSupportedIdTokenEncryptionMethods();

    try {
        allowedGrants = new ArrayList<String>(Arrays.asList(client.getAllowedOAuthGrantTypes()));
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
    try {
        scopeValidators = new ArrayList<String>(Arrays.asList(client.getAllowedScopeValidators()));
        // Sorting the list to display the scope validators in alphabetical order
        Collections.sort(scopeValidators);
        tokenTypes = new ArrayList<String>(Arrays.asList(client.getSupportedTokenTypes()));
    } catch (Exception e) {
        String message = resourceBundle.getString("error.while.getting.scope.validators") + " : " + e.getMessage();
        CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.ERROR, request, e);
%>
<script type="text/javascript">
    function forward() {
        location.href = "<%=forwardTo%>";
    }
</script>
<%
    }
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

                var audienceArr = [];

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
                    var oidcLogoutType = $('input[name=logoutMechanism]:checked').val();
                    var oidcLogoutUrl = document.getElementById('logout_url').value;
                    var userTokenExpiryTime = document.getElementById("userAccessTokenExpiryTime").value;
                    var applicationTokenExpiryTime = document.getElementById("userAccessTokenExpiryTime").value;
                    var refreshTokenExpiryTime = document.getElementById("refreshTokenExpiryTime").value;

                    if (callbackUrl.indexOf("#") !== -1) {
                        CARBON.showWarningDialog('<fmt:message key="callback.is.fragment"/>');
                        return false;
                    }

                    if (oidcLogoutUrl.indexOf("#") !== -1) {
                        CARBON.showWarningDialog('<fmt:message key="logout.url.is.fragment"/>');
                        return false;
                    }

                    var value = document.getElementsByName("application")[0].value;
                    if (value == '') {
                        CARBON.showWarningDialog('<fmt:message key="application.is.required"/>');
                        return false;
                    }
                    if (!$(jQuery("#grant_refresh_token"))[0].checked) {
                        document.getElementById("renewRefreshTokenPerApp").checked = true;
                        document.getElementById("renewRefreshTokenPerApp").value = 'notAssigned';
                    }

                    var version2Checked = document.getElementById("oauthVersion20").checked;
                    if (version2Checked) {
                        if (!$(jQuery("#grant_authorization_code"))[0].checked && !$(jQuery("#grant_implicit"))[0].checked) {
                            document.getElementsByName("callback")[0].value = '';
                        } else {
                            // This is to support providing regex patterns for callback URLs
                            if (callbackUrl.startsWith("regexp=")) {
                                // skip validation
                            } else if (!(isWhiteListed(callbackUrl, ["https-url"]) || isWhiteListed(callbackUrl, ["http-url"])) || !isNotBlackListed(callbackUrl, ["uri-unsafe-exists"])) {
                                CARBON.showWarningDialog('<fmt:message key="callback.is.not.url"/>');
                                return false;
                            }

                            if (oidcLogoutType === "<%= OAuthConstants.OIDCConfigProperties.BACK_CHANNEL_LOGOUT%>") {
                                if (!(isWhiteListed(oidcLogoutUrl, ["https-url"]) || isWhiteListed(oidcLogoutUrl, ["http-url"])) || !isNotBlackListed(oidcLogoutUrl,
                                    ["uri-unsafe-exists"])) {
                                    CARBON.showWarningDialog('<fmt:message key="logout.is.not.url"/>');
                                    return false;
                                }
                            } else if (oidcLogoutType === "<%= OAuthConstants.OIDCConfigProperties.FRONT_CHANNEL_LOGOUT%>") {
                                if (!isWhiteListed(oidcLogoutUrl, ["https-url"]) || !isNotBlackListed(oidcLogoutUrl, ["uri-unsafe-exists"])) {
                                    CARBON.showWarningDialog('<fmt:message key="logout.is.not.https.url"/>');
                                    return false;
                                }
                            }
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
                        // This is to support providing regex patterns for callback URLs
                        if (callbackUrl.startsWith("regexp=")) {
                            // skip validation
                        } else if (!(isWhiteListed(callbackUrl, ["https-url"]) || isWhiteListed(callbackUrl, ["http-url"])) || !isNotBlackListed(callbackUrl, ["uri-unsafe-exists"])) {
                            CARBON.showWarningDialog('<fmt:message key="callback.is.not.url"/>');
                            return false;
                        }
                    }
                    document.addAppform.submit();
                }

                function adjustForm() {
                    var oauthVersion = $('input[name=oauthVersion]:checked').val();
                    var supportGrantCode = $('input[name=grant_authorization_code]:checked').val() != null;
                    var supportImplicit = $('input[name=grant_implicit]:checked').val() != null;
                    var idTokenEncryptionEnabled = $('input[name=encryptIdToken]:checked').val() != null;
                    var grantRefreshToken = $('input[name=grant_refresh_token]:checked').val() != null;

                    if(oauthVersion == "<%=OAuthConstants.OAuthVersions.VERSION_1A%>") {
                        $(jQuery('#grant_row')).hide();
                        $(jQuery('#scope_validator_row')).hide();
                        $(jQuery('#access_token_type_row')).hide();
                        $(jQuery("#pkce_enable").hide());
                        $(jQuery("#pkce_support_plain").hide());
                        $(jQuery('#userAccessTokenPlain').hide());
                        $(jQuery('#applicationAccessTokenPlain').hide());
                        $(jQuery('#refreshTokenPlain').hide());
                        $(jQuery('#idTokenPlain').hide());
                        $(jQuery('#logout_mechanism_row').hide());
                        $(jQuery('#logout_url_row').hide());
                        $(jQuery("#audience_enable").hide());
                        $(jQuery("#add_audience").hide());
                        $(jQuery("#audience_table").hide());
                        $(jQuery("#validate_request_object_signature_row").hide());
                        $(jQuery("#encrypt_id_token_row").hide());
                        $(jQuery('#encryption_method_row')).hide();
                        $(jQuery('#encryption_algorithm_row')).hide();
                        $(jQuery('#callback_row')).show();
                        $(jQuery('#bypass_client_credentials').hide());
                        $(jQuery('#renew_refresh_token_per_app').hide());

                    } else if(oauthVersion == "<%=OAuthConstants.OAuthVersions.VERSION_2%>") {
                        $(jQuery('#grant_row')).show();
                        $(jQuery('#scope_validator_row')).show();
                        $(jQuery('#access_token_type_row')).show();
                        $(jQuery("#pkce_enable").show());
                        $(jQuery("#pkce_support_plain").show());
                        $(jQuery('#userAccessTokenPlain').show());
                        $(jQuery('#applicationAccessTokenPlain').show());
                        $(jQuery('#refreshTokenPlain').show());
                        $(jQuery('#idTokenPlain').show());
                        $(jQuery("#audience_enable").show());
                        $(jQuery("#add_audience").show());
                        $(jQuery("#audience_table").show());
                        $(jQuery("#validate_request_object_signature_row").show());
                        $(jQuery("#encrypt_id_token_row").show());
                        $(jQuery('#encryption_algorithm_row')).show();
                        $(jQuery('#encryption_method_row')).show();
                        $(jQuery('#bypass_client_credentials').show());
                        $(jQuery('#renew_refresh_token_per_app').show());

                        if (!supportGrantCode && !supportImplicit) {
                            $(jQuery('#callback_row')).hide();
                            $(jQuery('#logout_mechanism_row').hide());
                            $(jQuery('#logout_url_row').hide());
                        } else {
                            $(jQuery('#callback_row')).show();
                            $(jQuery('#logout_mechanism_row').show());
                            $(jQuery('#logout_url_row').show());
                        }
                        if (supportGrantCode) {
                            $(jQuery("#pkce_enable").show());
                            $(jQuery("#pkce_support_plain").show());
                        } else {
                            $(jQuery("#pkce_enable").hide());
                            $(jQuery("#pkce_support_plain").hide());
                        }
                        if (grantRefreshToken) {
                            $(jQuery("#renew_refresh_token_per_app").show());
                        } else {
                            $(jQuery("#renew_refresh_token_per_app").hide());
                        }

                        if (!idTokenEncryptionEnabled) {
                            $('select[name=idTokenEncryptionAlgorithm]').prop('disabled', true);
                            $('select[name=idTokenEncryptionMethod]').prop('disabled', true);
                        } else {
                            $('select[name=idTokenEncryptionAlgorithm]').prop('disabled', false);
                            $('select[name=idTokenEncryptionMethod]').prop('disabled', false);
                        }
                    }
                }

                function toggleAudienceRestriction(chkbx) {
                    document.addAppform.audience.disabled = !chkbx.checked;
                    document.addAppform.addAudience.disabled = !chkbx.checked;
                }

                function toggleOidcLogout(chkbx) {
                    document.addAppform.logoutUrl.disabled = !chkbx.checked;
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

                    var audiencePropertyTD = document.createElement('td');
                    audiencePropertyTD.setAttribute('style', 'color: rgb(119, 119, 119); font-style: italic;');
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
                    $(jQuery("#addAppForm input")).change(adjustForm);

                    // Set default encryption algorithm and encryption method read from identity.xml.
                    $('select[name=idTokenEncryptionAlgorithm]').val('<%=Encode.forJavaScriptAttribute(defaultIdTokenEncryptionAlgorithm)%>');
                    $('select[name=idTokenEncryptionMethod]').val('<%=Encode.forJavaScriptAttribute(defaultIdTokenEncryptionMethod)%>');
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

                                <tr id="grant_row" name="grant_row">
                                    <td class="leftCol-med"><fmt:message key='grantTypes'/></td>
                                    <td>
                                        <table>
                                            <%
                                                try {
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
                                <tr id="callback_row">
                                    <td class="leftCol-med"><fmt:message key='callback'/><span class="required">*</span></td>
                                    <td><input class="text-box-big" id="callback" name="callback" type="text"
                                               white-list-patterns="https-url"/></td>
                                </tr>
                                <tr id="pkce_enable">
                                    <td class="leftCol-med" colspan="2">
                                        <label>
                                            <input type="checkbox" name="pkce" value="mandatory"/>
                                            <fmt:message key='pkce.mandatory'/>
                                        </label>
                                        <div class="sectionHelp">
                                            <fmt:message key='pkce.mandatory.hint'/>
                                        </div>
                                    </td>
                                </tr>
                                <tr id="pkce_support_plain">
                                    <td colspan="2">
                                        <label>
                                            <input type="checkbox" name="pkce_plain" value="yes" checked>
                                            <fmt:message key='pkce.support.plain'/>
                                        </label>
                                        <div class="sectionHelp">
                                            <fmt:message key='pkce.support.plain.hint'/>
                                        </div>
                                    </td>
                                </tr>
                                <tr id="renew_refresh_token_per_app">
                                    <td colspan="2">
                                        <label>
                                            <input type="checkbox" name="renewRefreshTokenPerApp"
                                                   id="renewRefreshTokenPerApp" value="true"
                                                    <%=(client.isRefreshTokenRenewalEnabled() ? "checked" : "")%> />
                                            <fmt:message key='renew.refresh.token.per.app'/>
                                        </label>
                                        <div class="sectionHelp">
                                            <fmt:message key='renew.refresh.token.per.app.hint'/>
                                        </div>
                                    </td>
                                </tr>
                                <tr id="bypass_client_credentials">
                                    <td colspan="2">
                                        <label>
                                            <input type="checkbox" name="bypass_client_credentials" value="yes">
                                            <fmt:message key='bypassclientcreds.support.plain'/>
                                        </label>
                                        <div class="sectionHelp">
                                            <fmt:message key='bypassclientcreds.support.plain.hint'/>
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
                                <tr id="idTokenPlain">
                                    <td class="leftCol-med"><fmt:message key='id.token.expiry.time'/></td>
                                    <td>
                                        <input id="idTokenExpiryTime" name="idTokenExpiryTime" type="text" value="<%=client.getOAuthTokenExpiryTimeDTO().getIdTokenExpiryTime()%>" />
                                        <fmt:message key='seconds'/>
                                    </td>
                                </tr>
                                <tr id="audience_enable">
                                    <td colspan="2">
                                        <label title="Enable Audience Restriction to restrict the audience. You may add audience members using the Audience text box and clicking the Add button">
                                            <input type="checkbox" name="enableAudienceRestriction"
                                                   id="enableAudienceRestriction" value="true"
                                                   onclick="toggleAudienceRestriction(this);"/>
                                            <fmt:message key="enable.audience.restriction"/>
                                        </label>
                                    </td>
                                </tr>
                                <tr id="add_audience">
                                    <td style="padding-left: 40px ! important; color: rgb(119, 119, 119); font-style: italic;">
                                        <fmt:message key="sp.audience"/>
                                    </td>
                                    <td>
                                        <input type="text" id="audience" name="audience"
                                               class="text-box-big" disabled="disabled"/>
                                        <input id="addAudience" name="addAudience" type="button"
                                               disabled="disabled" value="<fmt:message key="oauth.add.audience"/>"
                                               onclick="return addAudienceFunc()"/>
                                    </td>
                                </tr>

                                <tr id="audience_table">
                                    <td></td>
                                    <td>
                                        <table id="audienceTableId"
                                               style="<%=audienceTableStyle%>"
                                               class="styledInner">
                                            <tbody id="audienceTableTbody">
                                            <%
                                                int j = 0;
                                            %>
                                            <input type="hidden" name="audiencePropertyCounter"
                                                   id="audiencePropertyCounter"
                                                   value="<%=j%>"/>
                                            </tbody>
                                        </table>
                                    </td>
                                </tr>
                                <!-- OIDC related properties -->
                                <tr id="validate_request_object_signature_row">
                                    <td colspan="2">
                                        <label title="Validate the signature of the request object">
                                            <input type="checkbox" name="validateRequestObjectSignature"
                                                   id="validateRequestObjectSignature" value="true"/>
                                            <fmt:message key='enable.request.object.signature.validation'/>
                                        </label>
                                    </td>
                                </tr>

                                <tr id="encrypt_id_token_row">
                                    <td colspan="2">
                                        <label title="Encrypt the id_token">
                                            <input type="checkbox" name="encryptIdToken" id="encryptIdToken"
                                                   value="true"/>
                                            <fmt:message key='enable.id.token.encryption'/>
                                        </label>
                                    </td>
                                </tr>

                                <tr id="encryption_algorithm_row">
                                    <td style="padding-left: 40px ! important;">
                                        <fmt:message key='id.token.encryption.algorithm'/>
                                    </td>
                                    <td>
                                        <select name="idTokenEncryptionAlgorithm" style="width: 250px;">
                                    <%
                                        for (String algorithm: supportedIdTokenEncryptionAlgorithms) {
                                            algorithm = Encode.forHtmlAttribute(algorithm);
                                    %>
                                            <option value="<%=algorithm%>"><%=algorithm%></option>
                                    <%
                                        }
                                    %>
                                        </select>
                                    </td>
                                </tr>
                                <tr id="encryption_method_row">
                                    <td style="padding-left: 40px ! important;">
                                        <fmt:message key='id.token.encryption.method'/>
                                    </td>
                                    <td>
                                        <select name="idTokenEncryptionMethod" style="width: 250px;">
                                    <%
                                        for (String method: supportedIdTokenEncryptionMethods) {
                                            method = Encode.forHtmlAttribute(method);
                                    %>
                                            <option value="<%=method%>"><%=method%></option>
                                    <%
                                        }
                                    %>
                                        </select>
                                    </td>
                                </tr>

                                <tr id="logout_mechanism_row">
                                    <td colspan="2">
                                        <label title="Enable OIDC Backchannel Logout. Add the Backchannel Logout Endpoint URL in the textbox below">
                                            <input type="checkbox" name="logoutMechanism"
                                                   id="backchannel_logout"
                                                   value="<%= Encode.forHtmlAttribute(OAuthConstants.OIDCConfigProperties.BACK_CHANNEL_LOGOUT)%>"
                                                   onclick="toggleOidcLogout(this)"/>
                                            <fmt:message key="oidc.backchannel.logout"/>
                                        </label>
                                    </td>
                                </tr>

                                <tr id="logout_url_row">
                                    <td class="leftCol-med" style="padding-left: 40px ! important;">
                                        <fmt:message key="logout.url"/>
                                    </td>
                                    <td>
                                        <input class="text-box-big" id="logout_url"
                                               name="logoutUrl" type="text"
                                               disabled="disabled"
                                        />
                                    </td>
                                </tr>

                                    <%--Scope validators--%>
                                <tr id="scope_validator_row" name="scope_validator_row">
                                    <td class="leftCol-med"><fmt:message key='scopeValidators'/></td>
                                    <td>
                                        <table>
                                            <%
                                                try {
                                                    for (String scopeValidator : scopeValidators) {

                                            %>
                                            <tr>
                                                <td><label><input type="checkbox"
                                                                  id=<%= OAuthUIUtil.getScopeValidatorId(scopeValidator)%>
                                                                          name=<%= OAuthUIUtil.getScopeValidatorId(scopeValidator)%>
                                                                  value=<%=Encode.forHtmlAttribute(OAuthUIUtil.getScopeValidatorId(scopeValidator))%>/><%=Encode.forHtmlAttribute(scopeValidator)%>
                                                </label></td>
                                            </tr>
                                            <%
                                                }
                                            } catch (Exception e) {
                                                String message = resourceBundle.getString("error.while.getting.scope.validators") + " : " + e.getMessage();
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
                                <!--Access Token types-->
                                <tr id="access_token_type_row" name="access_token_type_row">
                                    <td class="leftCol-med"><fmt:message key='accessTokenTypes'/></td>
                                    <td>
                                        <table>
                                            <%
                                                for (String tokenType : tokenTypes) {
                                            %>
                                            <tr>
                                                <td><label><input type="radio" name="tokenType"
                                                                  id=<%=  OAuthUIUtil.getTokenTypeId(tokenType)%>
                                                                          value=<%=Encode.forHtmlAttribute(tokenType)%>
                                                        <%
                                                            if (tokenType.equalsIgnoreCase(DEFAULT_TOKEN_TYPE)) {
                                                        %> checked="checked" <%}%> />
                                                    <%=Encode.forHtmlAttribute(tokenType)%>
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
                            <% } %>
                        </td>
                    </tr>
                    </tbody>
                </table>

            </form>
        </div>
    </div>
</fmt:bundle>
