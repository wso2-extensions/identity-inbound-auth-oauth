/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.openidconnect;

import com.nimbusds.jwt.JWTClaimsSet;
import net.minidev.json.JSONArray;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.json.JSONObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.xml.XMLObject;
import org.w3c.dom.Element;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.RoleMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.registry.api.RegistryException;
import org.wso2.carbon.registry.api.Resource;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

/**
 * Returns the claims of the SAML assertion
 */
public class SAMLAssertionClaimsCallback implements CustomClaimsCallbackHandler {

    private final static Log log = LogFactory.getLog(SAMLAssertionClaimsCallback.class);
    private final static String INBOUND_AUTH2_TYPE = "oauth2";
    private final static String SP_DIALECT = "http://wso2.org/oidc/claim";
    private static final String UPDATED_AT = "updated_at";
    private static final String PHONE_NUMBER_VERIFIED = "phone_number_verified";
    private static final String EMAIL_VERIFIED = "email_verified";
    private static final String ADDRESS_PREFIX = "address.";

    private static String userAttributeSeparator = IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;

    static {
        UserRealm realm;
        try {
            realm = OAuthComponentServiceHolder.getInstance().getRealmService().getTenantUserRealm
                    (MultitenantConstants.SUPER_TENANT_ID);
            UserStoreManager userStoreManager = realm.getUserStoreManager();
            userAttributeSeparator = ((org.wso2.carbon.user.core.UserStoreManager)userStoreManager)
                    .getRealmConfiguration().getUserStoreProperty(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);
        } catch (UserStoreException e) {
            log.warn("Error while reading MultiAttributeSeparator value from primary user store ", e);
        }
    }

    @Override
    public void handleCustomClaims(JWTClaimsSet jwtClaimsSet, OAuthTokenReqMessageContext requestMsgCtx) {
        // reading the token set in the same grant
        Assertion assertion = (Assertion) requestMsgCtx.getProperty(OAuthConstants.OAUTH_SAML2_ASSERTION);

        if (assertion != null) {

            if (assertion.getSubject() != null) {
                String subject = assertion.getSubject().getNameID().getValue();
                if (log.isDebugEnabled()){
                    log.debug("NameID in Assertion " + subject);
                }
                jwtClaimsSet.setSubject(subject);
            }

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
                                jwtClaimsSet.setClaim(attribute.getName(), attributeValues);
                            }
                        }
                    }
                }
            } else {
                log.debug("No AttributeStatement found! ");
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Adding claims for user " + requestMsgCtx.getAuthorizedUser() + " to id token.");
            }
            try {
                Map<String, Object> claims = getResponse(requestMsgCtx);
                setClaimsToJwtClaimSet(claims, jwtClaimsSet);
            } catch (OAuthSystemException e) {
                log.error("Error occurred while adding claims of " + requestMsgCtx.getAuthorizedUser() +
                                " to id token.", e);
            }
        }
    }

    @Override
    public void handleCustomClaims(JWTClaimsSet jwtClaimsSet, OAuthAuthzReqMessageContext requestMsgCtx) {

        if (log.isDebugEnabled()) {
            log.debug("Adding claims for user " + requestMsgCtx.getAuthorizationReqDTO().getUser() + " to id token.");
        }
        try {
            Map<String, Object> claims = getResponse(requestMsgCtx);
            setClaimsToJwtClaimSet(claims, jwtClaimsSet);
        } catch (OAuthSystemException e) {
            log.error("Error occurred while adding claims of " + requestMsgCtx.getAuthorizationReqDTO().getUser() +
                    " to id token.", e);
        }
    }

    /**
     * Get response map
     *
     * @param requestMsgCtx Token request message context
     * @return Mapped claimed
     * @throws OAuthSystemException
     */
    private Map<String, Object> getResponse(OAuthTokenReqMessageContext requestMsgCtx)
            throws OAuthSystemException {

        Map<ClaimMapping, String> userAttributes = Collections.emptyMap();
        Map<String, Object> claims = Collections.emptyMap();

        if (requestMsgCtx.getProperty(OAuthConstants.ACCESS_TOKEN) != null) {
            // get the user claims cached against the access token if any
            userAttributes = getUserAttributesFromCacheUsingToken(requestMsgCtx.getProperty(OAuthConstants
                    .ACCESS_TOKEN).toString());
        }

        if (MapUtils.isEmpty(userAttributes) && requestMsgCtx.getProperty(OAuthConstants.AUTHZ_CODE) != null) {
            // get the cached user claims against the authorization code if any
            userAttributes =
                    getUserAttributesFromCacheUsingCode(requestMsgCtx.getProperty(OAuthConstants.AUTHZ_CODE).toString());
        }

        if (MapUtils.isEmpty(userAttributes) && !requestMsgCtx.getAuthorizedUser().isFederatedUser()) {
            if (log.isDebugEnabled()) {
                log.debug("User attributes not found in cache. Trying to retrieve attribute for user " + requestMsgCtx
                        .getAuthorizedUser());
            }
            try {
                claims = getClaimsFromUserStore(requestMsgCtx);
            } catch (UserStoreException | IdentityApplicationManagementException | IdentityException e) {
                log.error("Error occurred while getting claims for user " + requestMsgCtx.getAuthorizedUser(), e);
            }
        } else {
            claims = getClaimsMap(userAttributes);
        }
        String tenantDomain = requestMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        return controlClaimsFromScope(requestMsgCtx.getScope(), tenantDomain, claims);
    }

    private Map<String, Object> getResponse(OAuthAuthzReqMessageContext requestMsgCtx)
            throws OAuthSystemException {

        Map<ClaimMapping, String> userAttributes = Collections.emptyMap();
        Map<String, Object> claims = Collections.emptyMap();

        if (requestMsgCtx.getProperty(OAuthConstants.ACCESS_TOKEN) != null) {
            // get the user claims cached against the access token if any
            userAttributes = getUserAttributesFromCacheUsingToken(requestMsgCtx.getProperty(OAuthConstants
                    .ACCESS_TOKEN).toString());
        }

        if (MapUtils.isEmpty(userAttributes) && !(requestMsgCtx.getAuthorizationReqDTO().getUser().isFederatedUser())) {
            if (log.isDebugEnabled()) {
                log.debug("User attributes not found in cache. Trying to retrieve attribute for user " + requestMsgCtx
                        .getAuthorizationReqDTO().getUser());
            }
            try {
                claims = getClaimsFromUserStore(requestMsgCtx);
            } catch (UserStoreException | IdentityApplicationManagementException | IdentityException e) {
                log.error("Error occurred while getting claims for user " + requestMsgCtx.getAuthorizationReqDTO().getUser(),
                        e);
            }
        } else {
            claims = getClaimsMap(userAttributes);
        }
        String tenantDomain = requestMsgCtx.getAuthorizationReqDTO().getTenantDomain();
        return controlClaimsFromScope(requestMsgCtx.getApprovedScope(), tenantDomain, claims);
    }

    /**
     * Get claims map
     *
     * @param userAttributes User Attributes
     * @return User attribute map
     */
    private Map<String, Object> getClaimsMap(Map<ClaimMapping, String> userAttributes) {

        Map<String, Object> claims = new HashMap();
        if (MapUtils.isNotEmpty(userAttributes)) {
            for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                claims.put(entry.getKey().getRemoteClaim().getClaimUri(), entry.getValue());
            }
        }
        return claims;
    }

    /**
     * Get claims from user store
     *
     * @param requestMsgCtx Token request message context
     * @return Users claim map
     * @throws Exception
     */
    private static Map<String, Object> getClaimsFromUserStore(OAuthTokenReqMessageContext requestMsgCtx)
            throws UserStoreException, IdentityApplicationManagementException, IdentityException {

        Map<String, Object> mappedAppClaims = new HashMap<>();

        String spTenantDomain = (String) requestMsgCtx.getProperty(MultitenantConstants.TENANT_DOMAIN);

        // There are certain flows where tenant domain is not added as a message context property.
        if (spTenantDomain == null) {
            spTenantDomain = requestMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
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
        if(requestedLocalClaimMap == null || !(requestedLocalClaimMap.length > 0)) {
            return new HashMap<>();
        }

        AuthenticatedUser user = requestMsgCtx.getAuthorizedUser();
        String userTenantDomain = user.getTenantDomain();
        String username = user.toString();
        UserRealm realm = IdentityTenantUtil.getRealm(userTenantDomain, username);
        if (realm == null) {
            log.warn("Invalid tenant domain provided. Empty claim returned back for tenant " + userTenantDomain
                     + " and user " + username);
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

        String domain = IdentityUtil.extractDomainFromName(username);
        RealmConfiguration realmConfiguration = ((org.wso2.carbon.user.core.UserStoreManager)realm
                .getUserStoreManager()).getSecondaryUserStoreManager(domain).getRealmConfiguration();
        String claimSeparator = realmConfiguration.getUserStoreProperty(
                IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);
        if (StringUtils.isBlank(claimSeparator)) {
            claimSeparator = IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;
        }

        Map<String, String> spToLocalClaimMappings = ClaimMetadataHandler.getInstance()
                .getMappingsMapFromOtherDialectToCarbon(SP_DIALECT, null, spTenantDomain, false);
        Map<String, String> userClaims = null;
        try {
            userClaims = realm.getUserStoreManager().getUserClaimValues(
                    MultitenantUtils.getTenantAwareUsername(username),
                    claimURIList.toArray(new String[claimURIList.size()]), null);

            //set local2sp role mappings
            for (Map.Entry<String, String> claim : userClaims.entrySet()) {
                if (FrameworkConstants.LOCAL_ROLE_CLAIM_URI.equals(claim.getKey())) {
                    String roleClaim = claim.getValue();
                    List<String> rolesList = new LinkedList<>(Arrays.asList(roleClaim.split(claimSeparator)));

                    String roles = getServiceProviderMappedUserRoles(serviceProvider, rolesList, claimSeparator);
                    claim.setValue(roles);
                    break;
                }
            }
        } catch (UserStoreException e) {
            if (e.getMessage().contains("UserNotFound")) {
                if (log.isDebugEnabled()) {
                    log.debug("User " + username + " not found in user store");
                }
            } else {
                throw e;
            }
        }

        if (MapUtils.isEmpty(userClaims)) {
	     if (log.isDebugEnabled()) {
	         log.debug("Number of user claims retrieved from user store: none (userClaims is null");
	    }
            return new HashMap<>();
        }
        
        if (log.isDebugEnabled()) {
            log.debug("Number of user claims retrieved from user store: " + userClaims.size());
        }


        for (Iterator<Map.Entry<String, String>> iterator = spToLocalClaimMappings.entrySet().iterator(); iterator
                .hasNext(); ) {
            Map.Entry<String, String> entry = iterator.next();
            String value = userClaims.get(entry.getValue());
            if (value != null) {
                mappedAppClaims.put(entry.getKey(), value);
                if (log.isDebugEnabled() &&
                        IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                    log.debug("Mapped claim: key -  " + entry.getKey() + " value -" + value);
                }
            }
        }

        if (StringUtils.isNotBlank(claimSeparator)) {
            mappedAppClaims.put(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR, claimSeparator);
        }

        return mappedAppClaims;
    }

    /**
     * @param serviceProvider
     * @param locallyMappedUserRoles
     * @return
     */
    private static String getServiceProviderMappedUserRoles(ServiceProvider serviceProvider,
                                                            List<String> locallyMappedUserRoles,
                                                            String claimSeparator) throws FrameworkException {

        if (CollectionUtils.isNotEmpty(locallyMappedUserRoles)) {
            // Get Local Role to Service Provider Role mappings
            RoleMapping[] localToSpRoleMapping = serviceProvider.getPermissionAndRoleConfig().getRoleMappings();

            if (ArrayUtils.isNotEmpty(localToSpRoleMapping)) {
                for (RoleMapping roleMapping : localToSpRoleMapping) {
                    // check whether a local role is mapped to service provider role
                    if (locallyMappedUserRoles.contains(roleMapping.getLocalRole().getLocalRoleName())) {
                        // remove the local role from the list of user roles
                        locallyMappedUserRoles.remove(roleMapping.getLocalRole().getLocalRoleName());
                        // add the service provider mapped role
                        locallyMappedUserRoles.add(roleMapping.getRemoteRole());
                    }
                }
            }
        }

        return StringUtils.join(locallyMappedUserRoles, claimSeparator);
    }

    private static Map<String, Object> getClaimsFromUserStore(OAuthAuthzReqMessageContext requestMsgCtx)
            throws IdentityApplicationManagementException, IdentityException, UserStoreException {

        Map<String, Object> mappedAppClaims = new HashMap<>();

        String spTenantDomain = (String) requestMsgCtx.getProperty(MultitenantConstants.TENANT_DOMAIN);

        // There are certain flows where tenant domain is not added as a message context property.
        if (spTenantDomain == null) {
            spTenantDomain = requestMsgCtx.getAuthorizationReqDTO().getTenantDomain();
        }

        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        String spName = applicationMgtService
                .getServiceProviderNameByClientId(requestMsgCtx.getAuthorizationReqDTO().getConsumerKey(),
                        INBOUND_AUTH2_TYPE, spTenantDomain);
        ServiceProvider serviceProvider = applicationMgtService.getApplicationExcludingFileBasedSPs(spName,
                spTenantDomain);
        if (serviceProvider == null) {
            return mappedAppClaims;
        }
        ClaimMapping[] requestedLocalClaimMap = serviceProvider.getClaimConfig().getClaimMappings();
        if(requestedLocalClaimMap == null || !(requestedLocalClaimMap.length > 0)) {
            return new HashMap<>();
        }

        AuthenticatedUser user = requestMsgCtx.getAuthorizationReqDTO().getUser();
        String userTenantDomain = user.getTenantDomain();
        String username = user.toString();
        UserRealm realm = IdentityTenantUtil.getRealm(userTenantDomain, username);
        if (realm == null) {
            log.warn("Invalid tenant domain provided. Empty claim returned back for tenant " + userTenantDomain
                    + " and user " + user);
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

        Map<String, String> spToLocalClaimMappings = ClaimMetadataHandler.getInstance().
                getMappingsMapFromOtherDialectToCarbon(SP_DIALECT, null, spTenantDomain, false);

        Map<String, String> userClaims = null;
        try {
            userClaims = realm.getUserStoreManager().getUserClaimValues(UserCoreUtil.addDomainToName(
                    user.getUserName(), user.getUserStoreDomain()), claimURIList.toArray(
                    new String[claimURIList.size()]),null);
        } catch (UserStoreException e) {
            if (e.getMessage().contains("UserNotFound")) {
                if (log.isDebugEnabled()) {
                    log.debug("User " + user + " not found in user store");
                }
            } else {
                throw e;
            }
        }
        if (MapUtils.isEmpty(userClaims)) {
 	    if (log.isDebugEnabled()) {
	        log.debug("Number of user claims retrieved from user store: none (userClaims is null");
	    }
            return new HashMap<>();
        }
        if (log.isDebugEnabled()) {
            log.debug("Number of user claims retrieved from user store: " + userClaims.size());
        }


        for (Iterator<Map.Entry<String, String>> iterator = spToLocalClaimMappings.entrySet().iterator(); iterator
                .hasNext(); ) {
            Map.Entry<String, String> entry = iterator.next();
            String value = userClaims.get(entry.getValue());
            if (value != null) {
                mappedAppClaims.put(entry.getKey(), value);
                if (log.isDebugEnabled() &&
                        IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                    log.debug("Mapped claim: key -  " + entry.getKey() + " value -" + value);
                }
            }
        }

        String domain = user.getUserStoreDomain();
        RealmConfiguration realmConfiguration = ((org.wso2.carbon.user.core.UserStoreManager)realm
                .getUserStoreManager()).getSecondaryUserStoreManager(domain).getRealmConfiguration();
        String claimSeparator = realmConfiguration.getUserStoreProperty(
                IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);
        if (StringUtils.isNotBlank(claimSeparator)) {
            mappedAppClaims.put(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR, claimSeparator);
        }

        return mappedAppClaims;
    }

    /**
     * Get user attribute cached against the access token
     *
     * @param accessToken Access token
     * @return User attributes cached against the access token
     */
    private Map<ClaimMapping, String> getUserAttributesFromCacheUsingToken(String accessToken) {

        AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(accessToken);
        AuthorizationGrantCacheEntry cacheEntry = AuthorizationGrantCache.getInstance()
                .getValueFromCacheByToken(cacheKey);

        return cacheEntry == null ? new HashMap<ClaimMapping, String>() : cacheEntry.getUserAttributes();

    }

    /**
     * Get user attributes cached against the authorization code
     *
     * @param authorizationCode Authorization Code
     * @return User attributes cached against the authorization code
     */
    private Map<ClaimMapping, String> getUserAttributesFromCacheUsingCode(String authorizationCode) {

        AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(authorizationCode);
        AuthorizationGrantCacheEntry cacheEntry = AuthorizationGrantCache.getInstance()
                .getValueFromCacheByCode(cacheKey);

        return cacheEntry == null ? new HashMap<ClaimMapping, String>() : cacheEntry.getUserAttributes();
    }

    /**
     * Set claims from a Users claims Map object to a JWTClaimsSet object
     * @param claims Users claims
     * @param jwtClaimsSet JWTClaimsSet object
     */
    private void setClaimsToJwtClaimSet(Map<String, Object> claims, JWTClaimsSet jwtClaimsSet) {
        JSONArray values;
        Object claimSeparator = claims.get(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);
        if (claimSeparator != null) {
            String claimSeparatorString = (String) claimSeparator;
            if(StringUtils.isNotBlank(claimSeparatorString)) {
                userAttributeSeparator = (String) claimSeparator;
            }
            claims.remove(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);
        }

        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            String value = entry.getValue().toString();
            values = new JSONArray();
            if (userAttributeSeparator != null && value.contains(userAttributeSeparator)) {
                StringTokenizer st = new StringTokenizer(value, userAttributeSeparator);
                while (st.hasMoreElements()) {
                    String attributeValue = st.nextElement().toString();
                    if (StringUtils.isNotBlank(attributeValue)) {
                        values.add(attributeValue);
                    }
                }
                jwtClaimsSet.setClaim(entry.getKey(), values);
            } else {
                jwtClaimsSet.setClaim(entry.getKey(), value);
            }
        }
    }

    /**
     * Use to control claims based on the requested scopes and defined scopes in the registry
     *
     * @param requestedScopes String[] requestedScopes
     * @param tenantDomain    String tenantDomain
     * @param claims          Object> claims
     * @return
     */
    private Map<String, Object> controlClaimsFromScope(String[] requestedScopes, String tenantDomain,
                                                       Map<String, Object> claims) {
        Resource oidcScopesResource = null;
        String requestedScopeClaims = null;
        String addressValues = null;
        String[] arrRequestedScopeClaims = null;
        Map<String, Object> returnClaims = new HashMap<>();
        Map<String, Object> claimsforAddressScope = new HashMap<>();
        try {
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            carbonContext.setTenantId(tenantId);
            carbonContext.setTenantDomain(tenantDomain);
            RegistryService registry = OAuth2ServiceComponentHolder.getRegistryService();
            oidcScopesResource = registry.getConfigSystemRegistry(tenantId).get(OAuthConstants.SCOPE_RESOURCE_PATH);
        } catch (RegistryException e) {
            log.error("Error while obtaining registry collection from :" + OAuthConstants.SCOPE_RESOURCE_PATH, e);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
        if (oidcScopesResource != null && oidcScopesResource.getProperties() != null) {
            addressValues = oidcScopesResource.getProperty("address");
        }

        for (String requestedScope : requestedScopes) {
            if (oidcScopesResource != null && oidcScopesResource.getProperties() != null) {
                Enumeration supporetdScopes = oidcScopesResource.getProperties().propertyNames();
                while (supporetdScopes.hasMoreElements()) {
                    String supportedScope = (String) supporetdScopes.nextElement();
                    if (supportedScope.equals(requestedScope)) {
                        requestedScopeClaims = oidcScopesResource.getProperty(requestedScope);
                        if (requestedScopeClaims.contains(",")) {
                            arrRequestedScopeClaims = requestedScopeClaims.split(",");
                        } else {
                            arrRequestedScopeClaims = new String[1];
                            arrRequestedScopeClaims[0] = requestedScopeClaims;
                        }
                        for (Map.Entry<String, Object> entry : claims.entrySet()) {
                            String requestedClaims = entry.getKey();
                            if (Arrays.asList(arrRequestedScopeClaims).contains(requestedClaims)) {
                                // Address claim is handled for both ways, where address claims are sent as "address."
                                // prefix or in address scope.
                                if (requestedClaims.contains(ADDRESS_PREFIX)) {
                                    claimsforAddressScope.put(entry.getKey().substring(ADDRESS_PREFIX.length()), claims.get(entry.getKey()));
                                } else if (addressValues.contains(requestedClaims)) {
                                    claimsforAddressScope.put(entry.getKey(), claims.get(entry.getKey()));
                                } else {
                                    returnClaims.put(entry.getKey(), claims.get(entry.getKey()));
                                }
                            }
                        }

                    }
                }
            }
        }
        if (claimsforAddressScope.size() > 0) {
            JSONObject jsonObject = new JSONObject();
            for (Map.Entry<String, Object> entry : claimsforAddressScope.entrySet()) {
                jsonObject.put(entry.getKey(), entry.getValue());
            }
            returnClaims.put("address", jsonObject);
        }
        if (returnClaims.containsKey(UPDATED_AT) && returnClaims.get(UPDATED_AT) != null) {
            if (returnClaims.get(UPDATED_AT) instanceof String) {
                returnClaims.put(UPDATED_AT, Integer.parseInt((String) (returnClaims.get(UPDATED_AT))));
            }
        }
        if (returnClaims.containsKey(PHONE_NUMBER_VERIFIED) && returnClaims.get(PHONE_NUMBER_VERIFIED) != null) {
            if (returnClaims.get(PHONE_NUMBER_VERIFIED) instanceof String) {
                returnClaims.put(PHONE_NUMBER_VERIFIED, (Boolean.valueOf((String)
                        (returnClaims.get(PHONE_NUMBER_VERIFIED)))));
            }
        }
        if (returnClaims.containsKey(EMAIL_VERIFIED) && returnClaims.get(EMAIL_VERIFIED) != null) {
            if (returnClaims.get(EMAIL_VERIFIED) instanceof String) {
                returnClaims.put(EMAIL_VERIFIED, (Boolean.valueOf((String) (returnClaims.get(EMAIL_VERIFIED)))));
            }
        }
        return returnClaims;
    }

}
