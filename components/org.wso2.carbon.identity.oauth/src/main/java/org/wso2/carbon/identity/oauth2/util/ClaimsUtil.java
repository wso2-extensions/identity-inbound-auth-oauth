/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.util;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.xml.XMLObject;
import org.w3c.dom.Element;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class ClaimsUtil {

    private static Log log = LogFactory.getLog(ClaimsUtil.class);

    private final static String INBOUND_AUTH2_TYPE = "oauth2";
    private final static String SP_DIALECT = "http://wso2.org/oidc/claim";

    public static boolean isInLocalDialect(Map<String, String> attributes) {
        Iterator<String> iterator = attributes.keySet().iterator();
        if (iterator.hasNext()) {
            return iterator.next().startsWith("http://wso2.org/claims/");
        }
        return false;
    }


    public static Map<String, String> convertFederatedClaimsToLocalDialect(Map<String, String> remoteClaims, ClaimMapping[]
            idPClaimMappings, String tenantDomain) {

        if (log.isDebugEnabled()) {
            StringBuilder claimUris = new StringBuilder();
            for (String key : remoteClaims.keySet()) {
                claimUris.append(key).append(",");
            }
            log.debug("Converting federated user claims to local dialect. Converting claim urls: " + claimUris
                    .toString());
        }

        if (idPClaimMappings != null && idPClaimMappings.length > 0) {
            Map<String, String> localToIdPClaimMap;
            localToIdPClaimMap = FrameworkUtils.getClaimMappings(idPClaimMappings, true);
            Map<String, String> defaultValuesForClaims = loadDefaultValuesForClaims(idPClaimMappings);

            // Loop remote claims and map to local claims
            Map<String, String> convertedClaims = mapRemoteClaimsToLocalClaims(remoteClaims, localToIdPClaimMap,
                    defaultValuesForClaims);
            if (log.isDebugEnabled()) {
                StringBuilder claimUris = new StringBuilder();
                for (String key : convertedClaims.keySet()) {
                    claimUris.append(key).append(",");
                }
                log.debug("Converted federated user claims to local dialect. Converting claim urls: " + claimUris
                        .toString());
            }
            return convertedClaims;
        } else {
            // If idp claim mappings are not configured, return original claims.
            return remoteClaims;
        }

    }

    public static Map<String, String> convertClaimsToOIDCDialect(OAuthTokenReqMessageContext requestMsgCtx,
                                                                 Map<String, String> userClaims) throws
            IdentityApplicationManagementException, IdentityException {

        Map<String, String> mappedAppClaims = new HashMap<>();

        if (log.isDebugEnabled()) {
            StringBuilder claimUris = new StringBuilder();
            for (String key : userClaims.keySet()) {
                claimUris.append(key).append(",");
            }
            log.debug("Converting user claims from local dialect to OIDC dialect for user: " + requestMsgCtx
                    .getAuthorizedUser() + ", client id:" + requestMsgCtx.getOauth2AccessTokenReqDTO().getClientId()
                    + ", converting claim urls: " + claimUris.toString());
        }

        String spTenantDomain = requestMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        if (StringUtils.isBlank(spTenantDomain)) {
            spTenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }

        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        String spName = applicationMgtService
                .getServiceProviderNameByClientId(requestMsgCtx.getOauth2AccessTokenReqDTO().getClientId(),
                        INBOUND_AUTH2_TYPE, spTenantDomain);
        ServiceProvider serviceProvider = applicationMgtService.getApplicationExcludingFileBasedSPs(spName,
                spTenantDomain);
        if (serviceProvider == null) {
            return mappedAppClaims;
        }
        ClaimMapping[] requestedLocalClaimMap = serviceProvider.getClaimConfig().getClaimMappings();
        if (requestedLocalClaimMap == null || !(requestedLocalClaimMap.length > 0)) {
            return new HashMap<>();
        }

        List<String> claimURIList = new ArrayList<>();
        for (ClaimMapping mapping : requestedLocalClaimMap) {
            if (mapping.isRequested()) {
                claimURIList.add(mapping.getLocalClaim().getClaimUri());
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Requested number of local claims: " + claimURIList.size());
        }

        Map<String, String> spToLocalClaimMappings = ClaimMetadataHandler.getInstance()
                .getMappingsMapFromOtherDialectToCarbon(SP_DIALECT, null, spTenantDomain, false);

        for (Map.Entry<String, String> entry : spToLocalClaimMappings.entrySet()) {
            String value = userClaims.get(entry.getValue());
            if (value != null) {
                mappedAppClaims.put(entry.getKey(), value);
                if (log.isDebugEnabled() &&
                        IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                    log.debug("Mapped claim: key -  " + entry.getKey() + " value -" + value);
                }
            }
        }

        if (log.isDebugEnabled()) {
            StringBuilder claimUris = new StringBuilder();
            for (String key : mappedAppClaims.keySet()) {
                claimUris.append(key).append(",");
            }
            log.debug("Converted user claims from local dialect to OIDC dialect for user: " + requestMsgCtx
                    .getAuthorizedUser() + ", client id:" + requestMsgCtx.getOauth2AccessTokenReqDTO().getClientId()
                    + ", converted claim urls: " + claimUris.toString());
        }

        return mappedAppClaims;
    }

    public static Map<String, String> mapRemoteClaimsToLocalClaims(Map<String, String> remoteClaims,
                                                                   Map<String, String> localToIdPClaimMap,
                                                                   Map<String, String> defaultValuesForClaims) {

        Map<String, String> localUnfilteredClaims = new HashMap<>();
        for (Map.Entry<String, String> entry : localToIdPClaimMap.entrySet()) {
            String localClaimURI = entry.getKey();
            String claimValue = remoteClaims.get(localToIdPClaimMap.get(localClaimURI));
            if (StringUtils.isEmpty(claimValue)) {
                claimValue = defaultValuesForClaims.get(localClaimURI);
            }
            if (!StringUtils.isEmpty(claimValue)) {
                localUnfilteredClaims.put(localClaimURI, claimValue);
            }
        }

        return localUnfilteredClaims;
    }

    public static Map<String, String> loadDefaultValuesForClaims(ClaimMapping[] idPClaimMappings) {

        Map<String, String> defaultValuesForClaims = new HashMap<>();
        for (ClaimMapping claimMapping : idPClaimMappings) {
            String defaultValue = claimMapping.getDefaultValue();
            if (defaultValue != null && !defaultValue.isEmpty()) {
                defaultValuesForClaims.put(claimMapping.getLocalClaim().getClaimUri(), defaultValue);
            }
        }
        return defaultValuesForClaims;
    }

    public static Map<String, String> extractClaimsFromAssertion(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                                 OAuth2AccessTokenRespDTO responseDTO,
                                                                 Assertion assertion, String userAttributeSeparator) {

        Map<String, String> attributes = new HashMap<>();

        List<AttributeStatement> attributeStatementList = assertion.getAttributeStatements();
        if (CollectionUtils.isNotEmpty(attributeStatementList)) {
            for (AttributeStatement statement : attributeStatementList) {
                List<Attribute> attributesList = statement.getAttributes();
                for (Attribute attribute : attributesList) {
                    List<XMLObject> values = attribute.getAttributeValues();
                    String attributeValues = null;
                    if (values != null) {
                        for (int i = 0; i < values.size(); i++) {
                            Element value = attribute.getAttributeValues().get(i).getDOM();
                            String attributeValue = value.getTextContent();
                            if (log.isDebugEnabled()) {
                                log.debug("Attribute: " + attribute.getName() + ", Value: " + attributeValue);
                            }
                            if (StringUtils.isBlank(attributeValues)) {
                                attributeValues = attributeValue;
                            } else {
                                attributeValues += userAttributeSeparator + attributeValue;
                            }
                            attributes.put(attribute.getName(), attributeValues);
                        }
                    }
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("No AttributeStatement found in the request for client with id: " + tokReqMsgCtx
                        .getOauth2AccessTokenReqDTO().getClientId());
            }
        }

        return attributes;

    }
}
