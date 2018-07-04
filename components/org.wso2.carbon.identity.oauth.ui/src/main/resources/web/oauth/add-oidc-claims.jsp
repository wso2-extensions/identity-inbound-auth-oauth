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
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.util.List" %>
<%@page import="org.json.JSONObject" %>
<%@ page import="java.util.Arrays" %>
<%@ page import="org.wso2.carbon.context.PrivilegedCarbonContext" %>
<%@ page import="org.wso2.carbon.identity.core.util.IdentityTenantUtil" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIUtil" %>
<%@ page import="org.apache.axis2.context.ConfigurationContext" %>
<%@ page import="org.wso2.carbon.CarbonConstants" %>
<%@ page import="org.wso2.carbon.utils.ServerConstants" %>
<%@ page import="org.wso2.carbon.identity.oauth.ui.client.OAuthAdminClient" %>
<%@ page import="org.wso2.carbon.identity.claim.metadata.mgt.stub.dto.ExternalClaimDTO" %>
<%@ page import="org.wso2.carbon.identity.oauth.ui.client.ClaimMetadataAdminClient" %>
<%@ page import="static org.wso2.carbon.identity.oauth.ui.util.OAuthUIConstants.CLAIM_URI" %>
<%@ page import="static org.wso2.carbon.identity.oauth.ui.util.OAuthUIConstants.SCOPE_NAME" %>
<%@ page import="java.text.MessageFormat" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIMessage" %>
<%@ page import="java.util.ResourceBundle" %>
<jsp:include page="../dialog/display_messages.jsp"/>

<%
    final String OIDC_CLAIM_DIALECT = "http://wso2.org/oidc/claim";
    String BUNDLE = "org.wso2.carbon.identity.oauth.ui.i18n.Resources";
    ResourceBundle resourceBundle = ResourceBundle.getBundle(BUNDLE, request.getLocale());
    String scope = request.getParameter(SCOPE_NAME);
    String serverURL = CarbonUIUtil.getServerURL(config.getServletContext(), session);
    ConfigurationContext configContext = (ConfigurationContext)
            config.getServletContext().getAttribute(CarbonConstants.CONFIGURATION_CONTEXT);
    String cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_COOKIE);
    ClaimMetadataAdminClient client = new ClaimMetadataAdminClient(cookie, serverURL, configContext);
    List<ExternalClaimDTO> externalClaims = null;
    String[] claims = null;
    try {
        ExternalClaimDTO[] externalClaimDTOS = client.getExternalClaims(OIDC_CLAIM_DIALECT);
        
        OAuthAdminClient oAuthAdminClient = new OAuthAdminClient(cookie, serverURL, configContext);
        claims = oAuthAdminClient.getClaims(scope);
        List<ExternalClaimDTO> externalClaimsTemp = new ArrayList<ExternalClaimDTO>();
        externalClaims = new ArrayList<ExternalClaimDTO>(Arrays.asList(externalClaimDTOS));
        if (claims != null)
            for (String claim : claims) {
                for (ExternalClaimDTO externalClaimDTO : externalClaims) {
                    if (externalClaimDTO != null && claim.equals(externalClaimDTO.getExternalClaimURI())) {
                        externalClaimsTemp.add(externalClaimDTO);
                    }
                }
            }
        externalClaims.removeAll(externalClaimsTemp);
    } catch (Exception e) {
        String message = MessageFormat.format(resourceBundle.getString("error.while.adding.claims"), scope);
        CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.ERROR, request);
    }
%>

<fmt:bundle
        basename="org.wso2.carbon.identity.oauth.ui.i18n.Resources">
    <carbon:breadcrumb label="edit.oidc.claims"
                       resourceBundle="org.wso2.carbon.identity.oauth.ui.i18n.Resources"
                       topPage="true" request="<%=request%>"/>
    
    
    <div id="middle">
        <h2><fmt:message key="title.list.claims"/> <%=Encode.forHtml(scope)%>
        </h2>
    </div>
    
    
    <script type="text/javascript">
        function doCancel() {
            location.href = '<%=Encode.forJavaScriptBlock("list-oidc-scopes.jsp")%>';
        }
    </script>
    
    
    <style>
        #claimAddTable tbody tr td {
            border: 1px solid #cccccc !important;
        }
    </style>
    <script type="text/javascript">

        function doAdd() {
            document.dataForm.add.value = true;
            document.dataForm.action = "add-oidc-claims-finish-ajaxprocessor.jsp";
            if (doValidation() === true) {
                document.dataForm.submit();
            }
        }

        function doFinish() {
            document.dataForm.add.value = false;
            document.dataForm.action = "add-oidc-claims-finish-ajaxprocessor.jsp";
            document.dataForm.submit();


        }

        function doValidation() {
            var id = document.getElementById("claimrow_id_count").value;
            if (id == 0) {
                CARBON.showWarningDialog("Please add a OIDC claim to update the scope.");
                return false;
            }
            return true
        }

        var claimRowId = -1;
        jQuery(document).ready(function () {
            jQuery('#claimAddLink').click(function () {
                claimRowId++;
                var option = '<option value="">---Select Claim URI ---</option>';

                <% for(int i =0 ; i< externalClaims.size() ; i++){%>
                option += "<option value='" + '<%=Encode.forHtmlAttribute(getExternalClaims(externalClaims.get(i)))%>' + "'>" +
                    "<%=Encode.forHtmlAttribute(externalClaims.get(i).getExternalClaimURI())%>" + '</option>';
                <%}%>
                $("#claimrow_id_count").val(claimRowId + 1);
                var newrow = jQuery('<tr><td><select class="claimrow_wso2" name="claimrow_name_wso2_' + claimRowId + '">' + option + '</select></td> ' +
                    '<td><a onclick="deleteClaimRow(this)" class="icon-link" ' +
                    'style="background-image: url(images/delete.gif)">' +
                    'Delete' +
                    '</a></td></tr>');
                jQuery('.claimrow', newrow).blur(function () {
                    claimURIDropdownPopulator();
                });
                jQuery('#claimAddTable').append(newrow);
                if ($(jQuery('#claimAddTable tr')).length == 2) {
                    $(jQuery('#claimAddTable')).toggle();
                }
            })
        });
    </script>
    
    <script type="text/javascript">

        var deleteClaimRows = [];

        function deleteClaimRow(obj) {
            if (jQuery(obj).parent().prev().children()[0].value != '') {
                deleteClaimRows.push(jQuery(obj).parent().prev().children()[0].value);
            }
            jQuery(obj).parent().parent().remove();
            if ($(jQuery('#claimAddTable tr')).length == 1) {
                $(jQuery('#claimAddTable')).toggle();
            }
        }
    </script>
    <div id="middleArea">
    <div id="workArea">
        <div id="mainArea">
            <form method="post" action="add-oidc-claims-finish-ajaxprocessor.jsp" name="dataForm"
                  onsubmit="return doValidation();">
                <input type="hidden" name="scopeName" value=<%=Encode.forHtml(scope)%> id="scopeName"/>
                <input type="hidden" id="add" name="add" value="false"/>
                <table class="styledLeft" id="scopeAdd" width="60%">
                    <tbody>
                    <thead>
                    <tr style="white-space: nowrap">
                        <th class="leftCol-med"><fmt:message key="add.claim"/></th>
                    </tr>
                    </thead>
                    <tr>
                        <td class="formRaw">
                            <table class="normal" id="mainTable" style="width: 100%;">
                                
                                <tr>
                                    <td class="customClaim">
                                        <a id="claimAddLink" class="icon-link"
                                           style="margin-left:0;background-image:url(images/add.gif);"><fmt:message
                                                key='add.claim'/></a>
                                        
                                        <div style="clear:both"></div>
                                        
                                        <table class="styledLeft" id="claimAddTable" style="display:none">
                                            <thead>
                                            <tr>
                                                <th><fmt:message key='oidc.claims'/></th>
                                                <th><fmt:message key='actions'/></th>
                                            </tr>
                                            </thead>
                                        </table>
                                    </td>
                                </tr>
                                
                                <tr>
                                    <td>
                                        <input type="hidden" id="claimrow_id_count" name="claimrow_name_count"
                                               value="0">
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <td class="buttonRow">
                            <input type="button" class="button" value="<fmt:message key="add"/>"
                                   onclick="doAdd();"/>
                            <input type="button" class="button" value="<fmt:message key="finish"/>"
                                   onclick="doFinish();"/>
                            <input type="button" class="button" value="<fmt:message key="back"/>"
                                   onclick="doCancel();"/>
                        </td>
                    </tr>
                    </tbody>
                </table>
            </form>
        </div>
        <br/>
        <br/>
        <div id="view">
            <table class="styledLeft" width="100%" id="oidcClaims">
                <%
                    if (claims != null && claims.length > 0) {
                %>
                <tbody>
                <%
                    for (String claim : claims) {
                %>
                <tr>
                    <td>
                        <%if (claim != null) {%>
                        <%=Encode.forHtml(claim)%>
                        <%} else {%>
                        <label>No associated claims found.</label>
                        <%}%>
                    
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
        </div>
    </div>
</fmt:bundle>
<%!
    private String getExternalClaims(ExternalClaimDTO externalClaimDTO) {
        
        String claim = externalClaimDTO.getExternalClaimURI();
        JSONObject jsonObject = new JSONObject();
        jsonObject.put(CLAIM_URI, claim);
        return jsonObject.toString();
    }
%>

