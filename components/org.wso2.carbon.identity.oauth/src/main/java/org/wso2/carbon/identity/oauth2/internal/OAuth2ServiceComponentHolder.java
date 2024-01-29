/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.internal;

import org.wso2.carbon.identity.application.authentication.framework.AuthenticationDataPublisher;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationMethodNameTranslator;
import org.wso2.carbon.identity.application.authentication.framework.UserSessionManagementService;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.handler.HandlerComparator;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.oauth.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenProvider;
import org.wso2.carbon.identity.oauth.tokenprocessor.DefaultTokenProvider;
import org.wso2.carbon.identity.oauth.tokenprocessor.DefaultOAuth2RevocationProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.DefaultRefreshTokenGrantProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.OAuth2RevocationProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.RefreshTokenGrantProcessor;
import org.wso2.carbon.identity.oauth2.authz.validators.ResponseTypeRequestValidator;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthenticator;
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAO;
import org.wso2.carbon.identity.oauth2.dao.TokenManagementDAO;
import org.wso2.carbon.identity.oauth2.keyidprovider.KeyIDProvider;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinder;
import org.wso2.carbon.identity.openidconnect.ClaimProvider;
import org.wso2.carbon.identity.openidconnect.dao.ScopeClaimMappingDAO;
import org.wso2.carbon.identity.organization.management.role.management.service.RoleManager;
import org.wso2.carbon.identity.organization.management.service.OrganizationUserResidentResolverService;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.registry.core.service.RegistryService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * OAuth2 Service component data holder
 */
public class OAuth2ServiceComponentHolder {

    private static OAuth2ServiceComponentHolder instance = new OAuth2ServiceComponentHolder();
    private static ApplicationManagementService applicationMgtService;
    private static boolean pkceEnabled = false;
    private static boolean audienceEnabled = false;
    private static RegistryService registryService;
    private static AuthenticationMethodNameTranslator authenticationMethodNameTranslator;
    private static List<OAuthClientAuthenticator> authenticationHandlers = new ArrayList<>();
    private static List<ClaimProvider> claimProviders = new ArrayList<>();
    private static boolean idpIdColumnEnabled = false;
    private static boolean consentedTokenColumnEnabled = false;
    private List<TokenBinder> tokenBinders = new ArrayList<>();
    private Map<String, ResponseTypeRequestValidator> responseTypeRequestValidators = new HashMap<>();
    private OAuthAdminServiceImpl oauthAdminService;
    private static AuthenticationDataPublisher authenticationDataPublisherProxy;
    private static KeyIDProvider keyIDProvider = null;
    private IdpManager idpManager;
    private static UserSessionManagementService userSessionManagementService;
    private static RoleManager roleManager;
    private static OrganizationUserResidentResolverService organizationUserResidentResolverService;
    private List<ScopeDTO> oidcScopesClaims = new ArrayList<>();
    private List<Scope> oauthScopeBinding = new ArrayList<>();
    private ScopeClaimMappingDAO scopeClaimMappingDAO;
    private AccessTokenDAO accessTokenDAOService;
    private TokenManagementDAO tokenManagementDAOService;
    private RefreshTokenGrantProcessor refreshTokenGrantProcessor;
    private OAuth2RevocationProcessor revocationProcessor;
    private TokenProvider tokenProvider;

    private OAuth2ServiceComponentHolder() {

    }

    public static OAuth2ServiceComponentHolder getInstance() {

        return instance;
    }

    /**
     * Get Application management service
     *
     * @return ApplicationManagementService
     */
    public static ApplicationManagementService getApplicationMgtService() {

        return OAuth2ServiceComponentHolder.applicationMgtService;
    }

    /**
     * Set Application management service
     *
     * @param applicationMgtService ApplicationManagementService
     */
    public static void setApplicationMgtService(ApplicationManagementService applicationMgtService) {

        OAuth2ServiceComponentHolder.applicationMgtService = applicationMgtService;
    }

    @Deprecated
    public static boolean isPkceEnabled() {

        return pkceEnabled;
    }

    public static void setPkceEnabled(boolean pkceEnabled) {

        OAuth2ServiceComponentHolder.pkceEnabled = pkceEnabled;
    }

    public static boolean isAudienceEnabled() {

        return audienceEnabled;
    }

    public static void setAudienceEnabled(boolean audienceEnabled) {

        OAuth2ServiceComponentHolder.audienceEnabled = audienceEnabled;
    }

    public static boolean isIDPIdColumnEnabled() {

        return idpIdColumnEnabled;
    }

    public static void setIDPIdColumnEnabled(boolean idpIdColumnEnabled) {

        OAuth2ServiceComponentHolder.idpIdColumnEnabled = idpIdColumnEnabled;
    }

    public static boolean isConsentedTokenColumnEnabled() {

        return consentedTokenColumnEnabled;
    }

    public static void setConsentedTokenColumnEnabled(boolean consentedTokenColumnEnabled) {

        OAuth2ServiceComponentHolder.consentedTokenColumnEnabled = consentedTokenColumnEnabled;
    }

    public static RegistryService getRegistryService() {

        return registryService;
    }

    public static void setRegistryService(RegistryService registryService) {

        OAuth2ServiceComponentHolder.registryService = registryService;
    }

    public static void addAuthenticationHandler(OAuthClientAuthenticator clientAuthenticator) {

        authenticationHandlers.add(clientAuthenticator);
        authenticationHandlers.sort(new HandlerComparator());
    }

    public static List<OAuthClientAuthenticator> getAuthenticationHandlers() {

        return authenticationHandlers;
    }

    public static AuthenticationMethodNameTranslator getAuthenticationMethodNameTranslator() {

        return authenticationMethodNameTranslator;
    }

    public static void setAuthenticationMethodNameTranslator(
            AuthenticationMethodNameTranslator authenticationMethodNameTranslator) {

        OAuth2ServiceComponentHolder.authenticationMethodNameTranslator = authenticationMethodNameTranslator;
    }

    /**
     * Get ClaimProvider Service
     *
     * @return all ID token claims
     */
    public static List<ClaimProvider> getClaimProviders() {
        return claimProviders;
    }

    /**
     * Set ClaimProvider Service
     *
     * @param claimProvider
     */
    public static void setClaimProvider(ClaimProvider claimProvider) {

        OAuth2ServiceComponentHolder.claimProviders.add(claimProvider);
    }

    /**
     * Unregister the particular claimProvider
     *
     * @param claimProvider
     */
    public static void unregisterClaimProvider(ClaimProvider claimProvider) {

        claimProviders.remove(claimProvider);
    }

    public List<TokenBinder> getTokenBinders() {

        return tokenBinders;
    }

    public Optional<TokenBinder> getTokenBinder(String bindingType) {

        return tokenBinders.stream().filter(t -> t.getBindingType().equals(bindingType)).findAny();
    }

    public void addTokenBinder(TokenBinder tokenBinder) {

        this.tokenBinders.add(tokenBinder);
    }

    public void removeTokenBinder(TokenBinder tokenBinder) {

        this.tokenBinders.remove(tokenBinder);
    }

    public ResponseTypeRequestValidator getResponseTypeRequestValidator(String responseType) {

        return responseTypeRequestValidators.get(responseType);
    }

    public void addResponseTypeRequestValidator(ResponseTypeRequestValidator validator) {

        this.responseTypeRequestValidators.put(validator.getResponseType(), validator);
    }

    public void removeResponseTypeRequestValidator(ResponseTypeRequestValidator validator) {

        this.responseTypeRequestValidators.remove(validator.getResponseType());
    }

    public OAuthAdminServiceImpl getOAuthAdminService() {

        return oauthAdminService;
    }

    public void setOAuthAdminService(OAuthAdminServiceImpl oauthAdminService) {

        this.oauthAdminService = oauthAdminService;
    }

    /**
     * Set Authentication Data Publisher Proxy instance.
     *
     * @param authenticationDataPublisherProxy
     */
    public static void setAuthenticationDataPublisherProxy(AuthenticationDataPublisher
                                                                   authenticationDataPublisherProxy) {

        OAuth2ServiceComponentHolder.authenticationDataPublisherProxy = authenticationDataPublisherProxy;
    }

    /**
     * Get the Authentication Data Publisher Proxy instance.
     *
     * @return authenticationDataPublisherProxy instance.
     */
    public static AuthenticationDataPublisher getAuthenticationDataPublisherProxy() {

        return OAuth2ServiceComponentHolder.authenticationDataPublisherProxy;
    }

    /**
     * Method to get the configured KeyIDProvider implementation.
     *
     * @return configured Key ID Provider instance.
     */
    public static KeyIDProvider getKeyIDProvider() {

        return keyIDProvider;
    }

    /**
     * Method to add the KeyIDProvider.
     *
     * @param keyIDProvider instance of KeyIDProvider.
     */
    public static void setKeyIDProvider(KeyIDProvider keyIDProvider) {

        OAuth2ServiceComponentHolder.keyIDProvider = keyIDProvider;
    }

    /**
     * Set Idp manager Instance.
     *
     * @param idpManager IdpManager.
     */
    public void setIdpManager(IdpManager idpManager) {

        this.idpManager = idpManager;
    }

    /**
     * Get IdpManager Instance.
     *
     * @return IdpManager.
     */
    public IdpManager getIdpManager() {

        return idpManager;
    }
    
    /**
    * Set UserSessionManagementService Instance.
    *
    * @param userSessionManagementService UserSessionManagementService.
     */
    public static void setUserSessionManagementService(UserSessionManagementService userSessionManagementService) {

        OAuth2ServiceComponentHolder.userSessionManagementService = userSessionManagementService;
    }

    /**
     * Get UserSessionManagementService Instance.
     *
     * @return UserSessionManagementService.
     */
    public static UserSessionManagementService getUserSessionManagementService() {

        return userSessionManagementService;
    }

    public static RoleManager getRoleManager() {

        return roleManager;
    }

    public static void setRoleManager(RoleManager roleManager) {

        OAuth2ServiceComponentHolder.roleManager = roleManager;
    }

    public void setOIDCScopesClaims(List<ScopeDTO> oidcScopesClaims) {

        this.oidcScopesClaims = oidcScopesClaims;
    }

    public List<ScopeDTO> getOIDCScopesClaims() {

        return oidcScopesClaims;
    }

    public void setOauthScopeBinding(List<Scope> oauthScopeBinding) {

        this.oauthScopeBinding = oauthScopeBinding;
    }

    public List<Scope> getOauthScopeBinding() {

        return oauthScopeBinding;
    }


    public ScopeClaimMappingDAO getScopeClaimMappingDAO() {

        return scopeClaimMappingDAO;
    }

    public void setScopeClaimMappingDAO(ScopeClaimMappingDAO scopeClaimMappingDAO) {

        this.scopeClaimMappingDAO = scopeClaimMappingDAO;
    }

    public static OrganizationUserResidentResolverService getOrganizationUserResidentResolverService() {

        return organizationUserResidentResolverService;
    }

    public static void setOrganizationUserResidentResolverService(
            OrganizationUserResidentResolverService organizationUserResidentResolverService) {

        OAuth2ServiceComponentHolder.organizationUserResidentResolverService = organizationUserResidentResolverService;
    }

    /**
     * Get AccessTokenDAO instance.
     *
     * @return AccessTokenDAO {@link AccessTokenDAO} instance.
     */
    public AccessTokenDAO getAccessTokenDAOService() {

        return accessTokenDAOService;
    }

    /**
     * Set AccessTokenDAO instance.
     *
     * @param accessTokenDAOService {@link AccessTokenDAO} instance.
     */
    public void setAccessTokenDAOService(AccessTokenDAO accessTokenDAOService) {

        this.accessTokenDAOService = accessTokenDAOService;
    }

    /**
     * Get TokenManagementDAO instance.
     *
     * @return  TokenManagementDAO  {@link TokenManagementDAO} instance.
     */
    public TokenManagementDAO getTokenManagementDAOService() {

        return tokenManagementDAOService;
    }

    /**
     * Set TokenManagementDAO instance.
     *
     * @param tokenManagementDAOService {@link TokenManagementDAO} instance.
     */
    public void setTokenManagementDAOService(TokenManagementDAO tokenManagementDAOService) {

        this.tokenManagementDAOService = tokenManagementDAOService;
    }

    /**
     * Get Refresh Token Grant Processor.
     *
     * @return RefreshTokenGrantProcessor  Refresh Token Grant Processor.
     */
    public RefreshTokenGrantProcessor getRefreshTokenGrantProcessor() {

        if (refreshTokenGrantProcessor == null) {
            refreshTokenGrantProcessor = new DefaultRefreshTokenGrantProcessor();
        }
        return refreshTokenGrantProcessor;
    }

    /**
     * Set Refresh Token Grant Processor.
     *
     * @param refreshTokenGrantProcessor Refresh Token Grant Processor.
     */
    public void setRefreshTokenGrantProcessor(RefreshTokenGrantProcessor refreshTokenGrantProcessor) {

        this.refreshTokenGrantProcessor = refreshTokenGrantProcessor;
    }

    /**
     * Get Revocation Processor.
     *
     * @return Revocation Processor.
     */
    public OAuth2RevocationProcessor getRevocationProcessor() {

        if (revocationProcessor == null) {
            revocationProcessor = new DefaultOAuth2RevocationProcessor();
        }
        return revocationProcessor;
    }

    /**
     * Set Revocation Processor.
     *
     * @param revocationProcessor Revocation Processor.
     */
    public void setRevocationProcessor(OAuth2RevocationProcessor revocationProcessor) {

        this.revocationProcessor = revocationProcessor;
    }

    /**
     * Get token provider.
     *
     * @return TokenProvider
     */
    public TokenProvider getTokenProvider() {

        if (tokenProvider == null) {
            tokenProvider = new DefaultTokenProvider();
        }
        return tokenProvider;
    }

    /**
     * Set token provider.
     *
     * @param tokenProvider TokenProvider
     */
    public void setTokenProvider(TokenProvider tokenProvider) {

        this.tokenProvider = tokenProvider;
    }
}
