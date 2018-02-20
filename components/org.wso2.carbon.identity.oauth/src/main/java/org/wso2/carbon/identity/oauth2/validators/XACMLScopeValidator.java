/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */


package org.wso2.carbon.identity.oauth2.validators;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.axiom.om.xpath.AXIOMXPath;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jaxen.JaxenException;
import org.wso2.balana.utils.exception.PolicyBuilderException;
import org.wso2.balana.utils.policy.PolicyBuilder;
import org.wso2.balana.utils.policy.dto.RequestElementDTO;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.entitlement.EntitlementException;
import org.wso2.carbon.identity.entitlement.PDPConstants;
import org.wso2.carbon.identity.entitlement.common.EntitlementPolicyConstants;
import org.wso2.carbon.identity.entitlement.common.dto.RequestDTO;
import org.wso2.carbon.identity.entitlement.common.dto.RowDTO;
import org.wso2.carbon.identity.entitlement.common.util.PolicyCreatorUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import javax.xml.stream.XMLStreamException;


/**
 * The Scope Validation implementation. This uses XACML policies to evaluate scope validation defined by the user.
 */
public class XACMLScopeValidator extends OAuth2ScopeValidator {

    private static final String DECISION_XPATH = "//ns:Result/ns:Decision/text()";
    private static final String XACML_NS_PREFIX = "ns";
    private static final String ACTION_VALIDATE = "token_validation";
    private static final String RULE_EFFECT_PERMIT = "Permit";
    private static final String RULE_EFFECT_NOT_APPLICABLE = "NotApplicable";

    private static final String ACTION_CATEGORY = "http://wso2.org/identity/identity-action";
    private static final String SP_CATEGORY = "http://wso2.org/identity/sp";
    private static final String USER_CATEGORY = "http://wso2.org/identity/user";
    private static final String SCOPE_CATEGORY = "http://wso2.org/identity/oauth-scope";

    private static final String AUTH_ACTION_ID = ACTION_CATEGORY + "/action-name";
    private static final String SP_NAME_ID = SP_CATEGORY + "/sp-name";
    private static final String USERNAME_ID = USER_CATEGORY + "/username";
    private static final String USER_STORE_ID = USER_CATEGORY + "/user-store-domain";
    private static final String USER_TENANT_DOMAIN_ID = USER_CATEGORY + "/user-tenant-domain";
    private static final String SCOPE_ID = SCOPE_CATEGORY + "/scope-name";

    private Log log = LogFactory.getLog(XACMLScopeValidator.class);

    @Override
    public boolean validateScope(AccessTokenDO accessTokenDO, String resource) throws IdentityOAuth2Exception {

        if (isUnAuthorizedToken(accessTokenDO)) {
            return false;
        }
        String authzUser = accessTokenDO.getAuthzUser().getUserName();
        boolean isValidated = false;
        FrameworkUtils.startTenantFlow(accessTokenDO.getAuthzUser().getTenantDomain());
        try {
            String consumerKey = accessTokenDO.getConsumerKey();
            OAuthAppDO authApp = OAuth2Util.getAppInformationByClientId(consumerKey);

            if (log.isDebugEnabled()) {
                log.debug(String.format("Inside XACML based scope validation flow for access token of consumer key :" +
                                " %s of user %s", accessTokenDO.getConsumerKey(), authzUser));
            }

            RequestDTO requestDTO = createRequestDTO(accessTokenDO, authApp, resource);
            RequestElementDTO requestElementDTO = PolicyCreatorUtil.createRequestElementDTO(requestDTO);
            String requestString = PolicyBuilder.getInstance().buildRequest(requestElementDTO);

            if (log.isDebugEnabled()) {
                log.debug("XACML scope validation request :\n" + requestString);
            }
            String responseString = OAuth2ServiceComponentHolder.getEntitlementService().getDecision(requestString);
            if (log.isDebugEnabled()) {
                log.debug("XACML scope validation response :\n" + responseString);
            }
            String validationResponse = extractXACMLResponse(responseString);
            if (isResponseNotApplicable(validationResponse)) {
                log.warn(String.format(
                        "No applicable rule for service provider '%s@%s'. Add an validating policy (or unset Scope " +
                                "Validation using XACMLScopeValidator) to fix this warning.",
                        authApp.getApplicationName(), OAuth2Util.getTenantDomainOfOauthApp(authApp)));
                isValidated = true;
            } else if (isResponsePermit(validationResponse)) {
                isValidated = true;
            }
        } catch (InvalidOAuthClientException e) {
            log.error(String.format("Exception occurred when getting app information for client id %s of user %s. " +
                            "Error occurred when retrieving corresponding app for this specific client id  ",
                    accessTokenDO.getConsumerKey(), authzUser), e);
        } catch (PolicyBuilderException e) {
            log.error(String.format("Exception occurred when building  XACML request for token with id  %s of user %s.",
                    accessTokenDO.getTokenId(), authzUser), e);
        } catch (XMLStreamException | JaxenException e) {
            log.error(String.format("Exception occurred when reading XACML response for token with id %s of user %s.",
                    accessTokenDO.getTokenId(), authzUser), e);
        } catch (EntitlementException e) {
            log.error(String.format("Exception occurred when evaluating XACML request for token with id %s of user %s.",
                    accessTokenDO.getTokenId(), authzUser), e);
        } finally {
            FrameworkUtils.endTenantFlow();
        }
        return isValidated;
    }

    /**
     * Creates RequestDTO object for XACML request with the parameters retrieved from the access token
     *
     * @param accessTokenDO access token
     * @param authApp       OAuth app
     * @param resource      resource
     * @return RequestDTO
     */
    private RequestDTO createRequestDTO(AccessTokenDO accessTokenDO, OAuthAppDO authApp, String resource) {

        List<RowDTO> rowDTOs = new ArrayList<>();
        RowDTO actionDTO = createRowDTO(ACTION_VALIDATE, AUTH_ACTION_ID, ACTION_CATEGORY);
        RowDTO spNameDTO = createRowDTO(authApp.getApplicationName(), SP_NAME_ID, SP_CATEGORY);
        RowDTO usernameDTO = createRowDTO(accessTokenDO.getAuthzUser().getUserName(), USERNAME_ID, USER_CATEGORY);
        RowDTO userStoreDomainDTO = createRowDTO(accessTokenDO.getAuthzUser().getUserStoreDomain(), USER_STORE_ID,
                USER_CATEGORY);
        RowDTO userTenantDomainDTO = createRowDTO(accessTokenDO.getAuthzUser().getTenantDomain(),
                USER_TENANT_DOMAIN_ID, USER_CATEGORY);
        RowDTO resourceDTO = createRowDTO(resource, EntitlementPolicyConstants.RESOURCE_ID, PDPConstants
                .RESOURCE_CATEGORY_URI);

        rowDTOs.add(actionDTO);
        rowDTOs.add(spNameDTO);
        rowDTOs.add(usernameDTO);
        rowDTOs.add(userStoreDomainDTO);
        rowDTOs.add(userTenantDomainDTO);
        rowDTOs.add(resourceDTO);

        for (String scope : accessTokenDO.getScope()) {
            RowDTO scopeNameDTO = createRowDTO(scope, SCOPE_ID, SCOPE_CATEGORY);
            rowDTOs.add(scopeNameDTO);
        }
        RequestDTO requestDTO = new RequestDTO();
        requestDTO.setRowDTOs(rowDTOs);
        return requestDTO;
    }

    /**
     * Creates RowDTO object of xacml request using the resource name, attribute id, category value
     *
     * @param resourceName  resource name
     * @param attributeId   attribute id of the resource
     * @param categoryValue category of the resource
     * @return RowDTO
     */
    private RowDTO createRowDTO(String resourceName, String attributeId, String categoryValue) {

        RowDTO rowDTO = new RowDTO();
        rowDTO.setAttributeValue(resourceName);
        rowDTO.setAttributeDataType(EntitlementPolicyConstants.STRING_DATA_TYPE);
        rowDTO.setAttributeId(attributeId);
        rowDTO.setCategory(categoryValue);
        return rowDTO;
    }

    /**
     * This extracts the decision from the xacml response.
     *
     * @param xacmlResponse xacml response to be extracted
     * @return extracted decision
     * @throws XMLStreamException exception when converting string response to XML
     * @throws JaxenException     exception
     */
    private String extractXACMLResponse(String xacmlResponse) throws XMLStreamException, JaxenException {

        AXIOMXPath axiomxPath = new AXIOMXPath(DECISION_XPATH);
        axiomxPath.addNamespace(XACML_NS_PREFIX, EntitlementPolicyConstants.REQ_RES_CONTEXT_XACML3);
        OMElement rootElement = new StAXOMBuilder(new ByteArrayInputStream(xacmlResponse.getBytes(StandardCharsets
                .UTF_8))).getDocumentElement();
        return axiomxPath.stringValueOf(rootElement);
    }

    /**
     * decides whether the token have and authorized user.
     *
     * @param accessTokenDO access token
     * @return boolean
     */
    private boolean isUnAuthorizedToken(AccessTokenDO accessTokenDO) {
        if (accessTokenDO.getAuthzUser() == null) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("There is no authorized user for access token id %s ",
                        accessTokenDO.getTokenId()));
            }
            return true;
        }
        return false;
    }

    /**
     * decides whether the validation response is not applicable.
     *
     * @param validationResponse extracted decision of the XACML response
     * @return true if it is not applicable
     */
    private boolean isResponsePermit(String validationResponse) {
        return RULE_EFFECT_PERMIT.equalsIgnoreCase(validationResponse);
    }

    /**
     * decides whether the validation response is permit.
     *
     * @param validationResponse extracted decision of the XACML response
     * @return true if it is permit
     */
    private boolean isResponseNotApplicable(String validationResponse) {
        return RULE_EFFECT_NOT_APPLICABLE.equalsIgnoreCase(validationResponse);
    }

}
