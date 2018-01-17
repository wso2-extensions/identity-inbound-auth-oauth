/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package org.wso2.carbon.identity.oauth2.validators.scope;

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
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.validators.OAuth2ScopeValidator;
import org.wso2.carbon.identity.oauth2.validators.scope.constants.Constants;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import javax.xml.stream.XMLStreamException;

/**
 * The Scope Validation implementation. This uses XACML policies to evaluate token validation policy defined by the user.
 */
public class XACMLScopeValidator extends OAuth2ScopeValidator {

    private static final String DECISION_XPATH = "//ns:Result/ns:Decision/text()";
    private static final String XACML_NS = "urn:oasis:names:tc:xacml:3.0:core:schema:wd-17";
    private static final String XACML_NS_PREFIX = "ns";
    private static final String RULE_EFFECT_PERMIT = "Permit";
    private static final String RULE_EFFECT_NOT_APPLICABLE = "NotApplicable";
    private static final String ACTION_VALIDATE = "token_validation";
    private Log log = LogFactory.getLog(XACMLScopeValidator.class);

    @Override
    public boolean validateScope(AccessTokenDO accessTokenDO, String resource) throws IdentityOAuth2Exception {

        try {
            OAuthAppDO authApp = new OAuthAppDAO().getAppInformation(accessTokenDO.getConsumerKey());
            RequestDTO requestDTO = createRequestDTO(accessTokenDO, authApp, resource);
            RequestElementDTO requestElementDTO = PolicyCreatorUtil.createRequestElementDTO(requestDTO);
            String requestString = PolicyBuilder.getInstance().buildRequest(requestElementDTO);

            if (log.isDebugEnabled()) {
                log.debug("XACML Authorization request :\n" + requestString);
            }
            FrameworkUtils.startTenantFlow(accessTokenDO.getAuthzUser().getTenantDomain());
            String responseString =
                    OAuth2ServiceComponentHolder.getEntitlementService().getDecision(requestString);
            if (log.isDebugEnabled()) {
                log.debug("XACML Authorization response :\n" + responseString);
            }
            String authzResponse = evaluateXACMLResponse(responseString);
            boolean isAuthorized = false;
            if (RULE_EFFECT_NOT_APPLICABLE.equalsIgnoreCase(authzResponse)) {
                log.warn(String.format(
                        "No applicable rule for service provider '%s@%s', Hence validating the token by default. " +
                                "Add an validating policy (or unset validation) to fix this warning.",
                        authApp.getApplicationName(), accessTokenDO.getAuthzUser().getTenantDomain()));
                isAuthorized = true;
            } else if (RULE_EFFECT_PERMIT.equalsIgnoreCase(authzResponse)) {
                isAuthorized = true;
            }
            return isAuthorized;
        } catch (InvalidOAuthClientException e) {
            log.error("Invalid OAuth Client Exception occurred", e);
        } catch (PolicyBuilderException e) {
            log.error("Policy Builder Exception occurred", e);
        } catch (XMLStreamException | JaxenException e) {
            log.error("Exception occurred when getting decision from xacml response.", e);
        } catch (EntitlementException e) {
            log.error("Entitlement Exception occurred", e);
        } finally {
            FrameworkUtils.endTenantFlow();
        }
        return false;
    }

    private RequestDTO createRequestDTO(AccessTokenDO accessTokenDO, OAuthAppDO authApp, String resource) {
        List<RowDTO> rowDTOs = new ArrayList<>();
        RowDTO actionDTO =
                createRowDTO(ACTION_VALIDATE,
                        Constants.AUTH_ACTION_ID, Constants.ACTION_CATEGORY);
        RowDTO spNameDTO =
                createRowDTO(authApp.getApplicationName(),
                        Constants.SP_NAME_ID, Constants.SP_CATEGORY);
        RowDTO usernameDTO =
                createRowDTO(accessTokenDO.getAuthzUser().getUserName(),
                        Constants.USERNAME_ID, Constants.USER_CATEGORY);
        RowDTO userStoreDomainDTO =
                createRowDTO(accessTokenDO.getAuthzUser().getUserStoreDomain(),
                        Constants.USER_STORE_ID, Constants.USER_CATEGORY);
        RowDTO userTenantDomainDTO =
                createRowDTO(accessTokenDO.getAuthzUser().getTenantDomain(),
                        Constants.USER_TENANT_DOMAIN_ID, Constants.USER_CATEGORY);
        RowDTO resourceDTO = createRowDTO(resource, EntitlementPolicyConstants.RESOURCE_ID,
                PDPConstants.RESOURCE_CATEGORY_URI);

        rowDTOs.add(actionDTO);
        rowDTOs.add(spNameDTO);
        rowDTOs.add(usernameDTO);
        rowDTOs.add(userStoreDomainDTO);
        rowDTOs.add(userTenantDomainDTO);
        rowDTOs.add(resourceDTO);

        for (String scope : accessTokenDO.getScope()) {
            RowDTO scopeNameDTO =
                    createRowDTO(scope,
                            Constants.SCOPE_ID, Constants.SCOPE_CATEGORY);
            rowDTOs.add(scopeNameDTO);
        }
        RequestDTO requestDTO = new RequestDTO();
        requestDTO.setRowDTOs(rowDTOs);
        return requestDTO;
    }

    private RowDTO createRowDTO(String resourceName, String attributeId, String categoryValue) {

        RowDTO rowDTO = new RowDTO();
        rowDTO.setAttributeValue(resourceName);
        rowDTO.setAttributeDataType(EntitlementPolicyConstants.STRING_DATA_TYPE);
        rowDTO.setAttributeId(attributeId);
        rowDTO.setCategory(categoryValue);
        return rowDTO;

    }

    private String evaluateXACMLResponse(String xacmlResponse) throws XMLStreamException, JaxenException {

        AXIOMXPath axiomxPath = new AXIOMXPath(DECISION_XPATH);
        axiomxPath.addNamespace(XACML_NS_PREFIX, XACML_NS);
        OMElement rootElement =
                new StAXOMBuilder(new ByteArrayInputStream(xacmlResponse.getBytes(StandardCharsets.UTF_8)))
                        .getDocumentElement();
        return axiomxPath.stringValueOf(rootElement);

    }
}