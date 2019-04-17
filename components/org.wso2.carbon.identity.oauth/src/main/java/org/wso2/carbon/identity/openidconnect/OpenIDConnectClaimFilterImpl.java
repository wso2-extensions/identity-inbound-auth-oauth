/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.openidconnect;

import net.minidev.json.JSONObject;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.consent.ClaimMetaData;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.consent.exception.SSOConsentServiceException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.Claim;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.identity.openidconnect.model.RequestedClaim;
import org.wso2.carbon.registry.api.RegistryException;
import org.wso2.carbon.registry.api.Resource;
import org.wso2.carbon.registry.core.service.RegistryService;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

import static org.apache.commons.collections.MapUtils.isEmpty;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.ADDRESS;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.EMAIL_VERIFIED;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.PHONE_NUMBER_VERIFIED;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.UPDATED_AT;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.SCOPE_RESOURCE_PATH;

/**
 * Default implementation of {@link OpenIDConnectClaimFilter}
 * <p>
 * In our default implementation we filter the user claims (ie. user claims requested by the Service Provider) based
 * on allowed claims against each scope. For example, we can define a scope string (say scope1) and define a set of
 * claim uris in OIDC dialect against it. If the particular claim is requested by the SP and the scope value scope1
 * is requested then we will return the claim to be sent in id_token and user info.
 * <p>
 * In our current implementation this scope --> claim uris mapping is maintained in the registry /_system/config/oidc
 */
public class OpenIDConnectClaimFilterImpl implements OpenIDConnectClaimFilter {

    private static final String ADDRESS_PREFIX = "address.";
    private static final String ADDRESS_SCOPE = "address";
    private static final String OIDC_SCOPE_CLAIM_SEPARATOR = ",";

    private static final Log log = LogFactory.getLog(OpenIDConnectClaimFilterImpl.class);
    private static final int DEFAULT_PRIORITY = 100;

    @Override
    public Map<String, Object> getClaimsFilteredByOIDCScopes(Map<String, Object> userClaims,
                                                             String[] requestedScopes,
                                                             String clientId,
                                                             String spTenantDomain) {

        if (isEmpty(userClaims)) {
            // No user claims to filter.
            logDebugForEmptyUserClaims();
            return new HashMap<>();
        }

        Map<String, Object> claimsToBeReturned = new HashMap<>();
        Map<String, Object> addressScopeClaims = new HashMap<>();

        // Map<"openid", "first_name,last_name,username">
        Map<String, List<String>> scopeClaimsMap = new HashMap<>();
        int tenantId = IdentityTenantUtil.getTenantId(spTenantDomain);
        //load oidc scopes and mapped claims from the cache or db.
        List<ScopeDTO> oidcScopesList = getOIDCScopes(tenantId);
        for (ScopeDTO scope : oidcScopesList) {
            scopeClaimsMap.put(scope.getName(), Arrays.asList(scope.getClaim()));
        }
        if (MapUtils.isNotEmpty(scopeClaimsMap)) {
            List<String> addressScopeClaimUris = getAddressScopeClaimUris(scopeClaimsMap);
            // Iterate through scopes requested in the OAuth2/OIDC request to filter claims
            for (String requestedScope : requestedScopes) {
                // Check if requested scope is a supported OIDC scope value

                if (scopeClaimsMap.containsKey(requestedScope)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Requested scope: " + requestedScope + " is a defined OIDC Scope in tenantDomain: " +
                                spTenantDomain + ". Filtering claims based on the permitted claims in the scope.");
                    }
                    // Requested scope is an registered OIDC scope. Filter and return the claims belonging to the scope.
                    Map<String, Object> filteredClaims =
                            handleRequestedOIDCScope(userClaims, addressScopeClaims, scopeClaimsMap,
                                    addressScopeClaimUris, requestedScope);
                    claimsToBeReturned.putAll(filteredClaims);
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Requested scope: " + requestedScope + " is not a defined OIDC Scope in " +
                                "tenantDomain: " + spTenantDomain + ".");
                    }
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("No OIDC scopes defined for tenantDomain: " + spTenantDomain + ". Cannot proceed with " +
                        "filtering user claims therefore returning an empty claim map.");
            }
        }

        // Some OIDC claims need special formatting etc. These are handled below.
        if (isNotEmpty(addressScopeClaims)) {
            handleAddressClaim(claimsToBeReturned, addressScopeClaims);
        }

        handleUpdateAtClaim(claimsToBeReturned);
        handlePhoneNumberVerifiedClaim(claimsToBeReturned);
        handleEmailVerifiedClaim(claimsToBeReturned);

        return claimsToBeReturned;
    }

    @Override
    public List<String> getClaimsFilteredByOIDCScopes(Set<String> requestedScopes, String spTenantDomain) {

        // Map<"openid", "first_name,last_name,username">
        Map<String, List<String>> scopeClaimsMap = new HashMap<>();
        int tenantId = IdentityTenantUtil.getTenantId(spTenantDomain);
        List<String> filteredClaims = new ArrayList<>();
        //load oidc scopes and mapped claims from the cache or db.
        List<ScopeDTO> oidcScopesList = getOIDCScopes(tenantId);
        if (CollectionUtils.isNotEmpty(oidcScopesList)) {
            for (ScopeDTO scope : oidcScopesList) {
                scopeClaimsMap.put(scope.getName(), Arrays.asList(scope.getClaim()));
            }
            // Iterate through scopes requested in the OAuth2/OIDC request to filter claims
            for (String requestedScope : requestedScopes) {
                // Check if requested scope is a supported OIDC scope value
                if (scopeClaimsMap.containsKey(requestedScope)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Requested scope: " + requestedScope + " is a defined OIDC Scope in tenantDomain: " +
                                spTenantDomain + ". Filtering claims based on the permitted claims in the scope.");
                    }
                    // Requested scope is an registered OIDC scope. Filter and return the claims belonging to the scope.
                    filteredClaims.addAll(getClaimUrisInSupportedOIDCScope(scopeClaimsMap, requestedScope));
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Requested scope: " + requestedScope + " is not a defined OIDC Scope in " +
                                "tenantDomain: " + spTenantDomain + ".");
                    }
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("No OIDC scopes defined for tenantDomain: " + spTenantDomain + ". Cannot proceed with " +
                        "getting claims for the requested scopes. Therefore returning an empty claim list.");
            }
        }
        return filteredClaims;
    }

    @Override
    public Map<String, Object> getClaimsFilteredByUserConsent(Map<String, Object> userClaims,
                                                              AuthenticatedUser authenticatedUser,
                                                              String clientId,
                                                              String spTenantDomain) {

        if (isEmpty(userClaims)) {
            // No user claims to filter.
            logDebugForEmptyUserClaims();
            return new HashMap<>();
        }

        // Filter the claims based on the user consent.
        try {

            ServiceProvider serviceProvider = OAuth2Util.getServiceProvider(clientId, spTenantDomain);

            if (isConsentManagementServiceDisabled(serviceProvider)) {
                if (log.isDebugEnabled()) {
                    log.debug("Consent Management disabled or not applicable for Service Provider: "
                            + serviceProvider.getApplicationName() + ". Skipping filtering user claims based on consent.");
                }
                return userClaims;
            }

            List<String> userConsentedClaimUris = getUserConsentedLocalClaimURIs(authenticatedUser, serviceProvider);
            List<String> userConsentClaimUrisInOIDCDialect = getOIDCClaimURIs(userConsentedClaimUris, spTenantDomain);

            return userClaims.keySet().stream()
                    .filter(userConsentClaimUrisInOIDCDialect::contains)
                    .collect(Collectors.toMap(key -> key, userClaims::get));

        } catch (IdentityOAuth2Exception | SSOConsentServiceException e) {
            String msg = "Error while filtering claims based on user consent for user: " +
                    authenticatedUser.toFullQualifiedUsername() + " for client_id: " + clientId;
            log.error(msg, e);
        }

        return userClaims;
    }

    private boolean isConsentManagementServiceDisabled(ServiceProvider serviceProvider) {

        return !OpenIDConnectServiceComponentHolder.getInstance().getSsoConsentService()
                .isSSOConsentManagementEnabled(serviceProvider);
    }

    private List<String> getUserConsentedLocalClaimURIs(AuthenticatedUser authenticatedUser, ServiceProvider sp)
            throws SSOConsentServiceException {

        List<ClaimMetaData> claimsWithConsents = OpenIDConnectServiceComponentHolder.getInstance()
                .getSsoConsentService().getClaimsWithConsents(sp, authenticatedUser);
        return getClaimUrisWithConsent(claimsWithConsents);
    }

    @Override
    public int getPriority() {

        return DEFAULT_PRIORITY;
    }

    @Override
    public Map<String, Object> getClaimsFilteredByEssentialClaims(Map<String, Object> userClaims,
                                                                  List<RequestedClaim> requestParamClaims) {

        if (isEmpty(userClaims)) {
            // No user claims to filter.
            logDebugForEmptyUserClaims();
            return new HashMap<>();
        }

        Map<String, Object> essentialClaims = new HashMap<>();
        if (CollectionUtils.isNotEmpty(requestParamClaims)) {
            for (RequestedClaim essentialClaim : requestParamClaims) {
                String claimName = essentialClaim.getName();
                if (essentialClaim.isEssential() && userClaims.get(claimName) != null) {
                    List<String> values = essentialClaim.getValues();
                    if (CollectionUtils.isEmpty(values) && StringUtils.isNotEmpty(essentialClaim.getValue())) {
                        values = Collections.singletonList(essentialClaim.getValue());
                    }
                    if (CollectionUtils.isNotEmpty(values)) {
                        String userClaimValue = (String) userClaims.get(claimName);
                        if (values.contains(userClaimValue)) {
                            essentialClaims.put(claimName, userClaims.get(claimName));
                        }
                    } else {
                        essentialClaims.put(claimName, userClaims.get(claimName));
                    }

                }
            }
        }
        return essentialClaims;
    }

    private Properties getOIDCScopeProperties(String spTenantDomain) {

        Resource oidcScopesResource = null;
        try {
            int tenantId = IdentityTenantUtil.getTenantId(spTenantDomain);
            startTenantFlow(spTenantDomain, tenantId);

            RegistryService registryService = OAuth2ServiceComponentHolder.getRegistryService();
            if (registryService == null) {
                throw new RegistryException("Registry Service not set in OAuth2 Component. Component may not have " +
                        "initialized correctly.");
            }

            oidcScopesResource = registryService.getConfigSystemRegistry(tenantId).get(SCOPE_RESOURCE_PATH);
        } catch (RegistryException e) {
            log.error("Error while obtaining registry collection from registry path:" + SCOPE_RESOURCE_PATH, e);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }

        Properties propertiesToReturn = new Properties();
        if (oidcScopesResource != null) {
            for (Object scopeProperty : oidcScopesResource.getProperties().keySet()) {
                String propertyKey = (String) scopeProperty;
                propertiesToReturn.setProperty(propertyKey, oidcScopesResource.getProperty(propertyKey));
            }
        } else {
            log.error("OIDC scope resource cannot be found at " + SCOPE_RESOURCE_PATH + " for tenantDomain: "
                    + spTenantDomain);
        }
        return propertiesToReturn;
    }

    private List<ScopeDTO> getOIDCScopes(int tenantId) {

        List<ScopeDTO> oidcScopesList = new ArrayList<>();
        try {
            oidcScopesList = OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().getScopes(tenantId);
        } catch (IdentityOAuth2Exception e) {
            log.error("Error while loading oidc scopes and claims for the tenant: " + tenantId);
        }
        return oidcScopesList;
    }

    private Map<String, Object> handleRequestedOIDCScope(Map<String, Object> userClaimsInOIDCDialect,
                                                         Map<String, Object> addressScopeClaims,
                                                         Map<String, List<String>> scopeClaimsMap,
                                                         List<String> addressScopeClaimUris,
                                                         String oidcScope) {

        Map<String, Object> filteredClaims = new HashMap<>();
        List<String> claimUrisInRequestedScope = getClaimUrisInSupportedOIDCScope(scopeClaimsMap, oidcScope);
        for (String scopeClaim : claimUrisInRequestedScope) {
            String oidcClaimUri = scopeClaim;
            boolean isAddressClaim = false;
            if (isAddressClaim(scopeClaim, addressScopeClaimUris)) {
                if (log.isDebugEnabled()) {
                    log.debug("Identified an address claim: " + scopeClaim + ". Removing \"address.\" prefix from " +
                            "the claimUri");
                }
                oidcClaimUri = removeAddressPrefix(scopeClaim);
                isAddressClaim = true;
            }
            // Check whether the user claims contain the permitted claim uri
            if (userClaimsInOIDCDialect.containsKey(oidcClaimUri)) {
                if (log.isDebugEnabled()) {
                    log.debug("Adding claim:" + oidcClaimUri + " into the filtered claims");
                }
                Object claimValue = userClaimsInOIDCDialect.get(oidcClaimUri);
                // User claim is allowed for this scope.
                if (isAddressClaim) {
                    addressScopeClaims.put(oidcClaimUri, claimValue);
                } else {
                    filteredClaims.put(oidcClaimUri, claimValue);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("No valid user claim value found for the claimUri:" + oidcClaimUri);
                }
            }
        }
        return filteredClaims;
    }

    /**
     * There can be situations where we have added a scope prefix to identify special claims.
     * <p>
     * For example, claims belonging to address can be prefixed as address.country, address.street. But when
     * returning we need to remove the prefix.
     *
     * @param scopeClaim claim uri defined in the OIDC Scope
     * @return Scope prefix removed claim URI
     */
    private String removeAddressPrefix(String scopeClaim) {

        return StringUtils.startsWith(scopeClaim, ADDRESS_PREFIX) ?
                StringUtils.substringAfterLast(scopeClaim, ADDRESS_PREFIX) : scopeClaim;
    }

    private void handleAddressClaim(Map<String, Object> returnedClaims,
                                    Map<String, Object> claimsforAddressScope) {

        if (MapUtils.isNotEmpty(claimsforAddressScope)) {
            final JSONObject jsonObject = new JSONObject();
            for (Map.Entry<String, Object> addressScopeClaimEntry : claimsforAddressScope.entrySet()) {
                jsonObject.put(addressScopeClaimEntry.getKey(), addressScopeClaimEntry.getValue());
            }
            returnedClaims.put(ADDRESS, jsonObject);
        }
    }

    private List<String> getAddressScopeClaimUris(Map<String, List<String>> scopeClaimsMap) {

        return getClaimUrisInSupportedOIDCScope(scopeClaimsMap, ADDRESS_SCOPE);
    }

    private boolean isAddressClaim(String scopeClaim, List<String> addressScopeClaims) {

        return StringUtils.startsWith(scopeClaim, ADDRESS_PREFIX) || addressScopeClaims.contains(scopeClaim);
    }

    private List<String> getClaimUrisInSupportedOIDCScope(Map<String, List<String>> scopeClaimsMap, String requestedScope) {

        List<String> requestedScopeClaimsList = new ArrayList<>();
        if (scopeClaimsMap.containsKey(requestedScope)) {
            requestedScopeClaimsList = scopeClaimsMap.get(requestedScope);
        }
        return requestedScopeClaimsList;
    }

    private void handleUpdateAtClaim(Map<String, Object> returnClaims) {

        if (returnClaims.containsKey(UPDATED_AT) && returnClaims.get(UPDATED_AT) != null &&
                returnClaims.get(UPDATED_AT) instanceof String) {

            // We should pass the updated_at claim in number of seconds from 1970-01-01T00:00:00Z as measured in UTC
            // until the date/time. So we have to convert the date (If stored in that format) value in to this format.
            long timeInMillis;
            Date date = getDateIfValidDateString((String) (returnClaims.get(UPDATED_AT)));
            if (date != null) {
                timeInMillis = date.getTime();
            } else {
                timeInMillis = Long.parseLong((String) (returnClaims.get(UPDATED_AT)));
            }
            returnClaims.put(UPDATED_AT, timeInMillis);
        }
    }

    private void handlePhoneNumberVerifiedClaim(Map<String, Object> returnClaims) {

        if (returnClaims.containsKey(PHONE_NUMBER_VERIFIED))
            if (returnClaims.get(PHONE_NUMBER_VERIFIED) != null) {
                if (returnClaims.get(PHONE_NUMBER_VERIFIED) instanceof String) {
                    returnClaims.put(PHONE_NUMBER_VERIFIED, (Boolean.valueOf((String)
                            (returnClaims.get(PHONE_NUMBER_VERIFIED)))));
                }
            }
    }

    private void handleEmailVerifiedClaim(Map<String, Object> returnClaims) {

        if (returnClaims.containsKey(EMAIL_VERIFIED) && returnClaims.get(EMAIL_VERIFIED) != null) {
            if (returnClaims.get(EMAIL_VERIFIED) instanceof String) {
                returnClaims.put(EMAIL_VERIFIED, (Boolean.valueOf((String) (returnClaims.get(EMAIL_VERIFIED)))));
            }
        }
    }

    private void startTenantFlow(String tenantDomain, int tenantId) {

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
        carbonContext.setTenantId(tenantId);
        carbonContext.setTenantDomain(tenantDomain);
    }

    private boolean isNotEmpty(Map<String, Object> claimsToBeReturned) {

        return claimsToBeReturned != null && !claimsToBeReturned.isEmpty();
    }

    private boolean isNotEmpty(Properties properties) {

        return properties != null && !properties.isEmpty();
    }

    /**
     * Return a Date object if the given string is a valid date string.
     *
     * @param dateString date string in yyyy-MM-dd'T'HH:mm:ss format.
     * @return Date object if success null otherwise.
     */
    private Date getDateIfValidDateString(String dateString) {

        Date date;
        try {
            date = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss").parse(dateString);
        } catch (Exception ex) {
            if (log.isDebugEnabled()) {
                log.debug("The given date string: " + dateString + " is not in correct date time format.");
            }
            return null;
        }
        return date;
    }

    private List<String> getOIDCClaimURIs(List<String> userConsentedClaimUris,
                                          String tenantDomain) {

        final String OIDC_DIALECT = "http://wso2.org/oidc/claim";
        try {
            List<ExternalClaim> externalClaims = OpenIDConnectServiceComponentHolder.getInstance()
                    .getClaimMetadataManagementService()
                    .getExternalClaims(OIDC_DIALECT, tenantDomain);

            return externalClaims.stream()
                    .filter(externalClaim -> userConsentedClaimUris.contains(externalClaim.getMappedLocalClaim()))
                    .map(Claim::getClaimURI)
                    .collect(Collectors.toList());
        } catch (ClaimMetadataException e) {
            String msg = "Error while trying to convert user consented claims to OIDC dialect in tenantDomain: "
                    + tenantDomain;
            log.error(msg);
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
        }

        return Collections.emptyList();
    }

    private List<String> getClaimUrisWithConsent(List<ClaimMetaData> claimsWithConsents) {

        return claimsWithConsents.stream().map(ClaimMetaData::getClaimUri).collect(Collectors.toList());
    }

    private void logDebugForEmptyUserClaims() {

        if (log.isDebugEnabled()) {
            log.debug("No user claims to filter. Returning an empty map of filtered claims.");
        }
    }
}
