/*
 * Copyright (c) 2014-2023, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
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

package org.wso2.carbon.identity.oauth2.internal;

import org.wso2.carbon.identity.api.resource.mgt.APIResourceManager;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationDataPublisher;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationMethodNameTranslator;
import org.wso2.carbon.identity.application.authentication.framework.UserSessionManagementService;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.mgt.AuthorizedAPIManagementService;
import org.wso2.carbon.identity.consent.server.configs.mgt.services.ConsentServerConfigsManagementService;
import org.wso2.carbon.identity.core.SAMLSSOServiceProviderManager;
import org.wso2.carbon.identity.core.handler.HandlerComparator;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.oauth.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth.tokenprocessor.DefaultOAuth2RevocationProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.DefaultRefreshTokenGrantProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.DefaultTokenProvider;
import org.wso2.carbon.identity.oauth.tokenprocessor.OAuth2RevocationProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.RefreshTokenGrantProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenProvider;
import org.wso2.carbon.identity.oauth2.OAuthAuthorizationRequestBuilder;
import org.wso2.carbon.identity.oauth2.authz.validators.ResponseTypeRequestValidator;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthenticator;
import org.wso2.carbon.identity.oauth2.keyidprovider.KeyIDProvider;
import org.wso2.carbon.identity.oauth2.responsemode.provider.ResponseModeProvider;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinder;
import org.wso2.carbon.identity.oauth2.token.handlers.claims.JWTAccessTokenClaimProvider;
import org.wso2.carbon.identity.openidconnect.ClaimProvider;
import org.wso2.carbon.identity.openidconnect.dao.ScopeClaimMappingDAO;
import org.wso2.carbon.identity.organization.management.role.management.service.RoleManager;
import org.wso2.carbon.identity.organization.management.service.OrganizationManagementInitialize;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.OrganizationUserResidentResolverService;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;

import java.util.ArrayList;
import java.util.Collections;
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
    private static Map<String, ResponseModeProvider> responseModeProviders;
    private static ResponseModeProvider defaultResponseModeProvider;
    private static boolean consentedTokenColumnEnabled = false;
    private static IdentityEventService identityEventService;
    private static boolean tokenExtendedTableExist = false;
    private List<TokenBinder> tokenBinders = new ArrayList<>();
    private Map<String, ResponseTypeRequestValidator> responseTypeRequestValidators = new HashMap<>();
    private OAuthAdminServiceImpl oauthAdminService;
    private OrganizationManager organizationManager;
    private RealmService realmService;
    private static AuthenticationDataPublisher authenticationDataPublisherProxy;
    private static KeyIDProvider keyIDProvider = null;
    private IdpManager idpManager;
    private static UserSessionManagementService userSessionManagementService;
    private static SAMLSSOServiceProviderManager samlSSOServiceProviderManager;
    private static RoleManager roleManager;
    private static OrganizationUserResidentResolverService organizationUserResidentResolverService;
    private List<ScopeDTO> oidcScopesClaims = new ArrayList<>();
    private List<Scope> oauthScopeBinding = new ArrayList<>();
    private ScopeClaimMappingDAO scopeClaimMappingDAO;
    private static List<String> jwtRenewWithoutRevokeAllowedGrantTypes = new ArrayList<>();
    private static ConsentServerConfigsManagementService consentServerConfigsManagementService;
    private static boolean restrictUnassignedScopes;
    private static ConfigurationContextService configurationContextService;
    private List<JWTAccessTokenClaimProvider> jwtAccessTokenClaimProviders = new ArrayList<>();
    private final List<OAuthAuthorizationRequestBuilder> oAuthAuthorizationRequestBuilders = new ArrayList<>();
    private boolean isOrganizationManagementEnabled = false;
    private RefreshTokenGrantProcessor refreshTokenGrantProcessor;
    private OAuth2RevocationProcessor revocationProcessor;
    private TokenProvider tokenProvider;
    private AuthorizedAPIManagementService authorizedAPIManagementService;
    private APIResourceManager apiResourceManager;
    private RoleManagementService roleManagementServiceV2;

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

    public static boolean isTokenExtendedTableExist() {

        return tokenExtendedTableExist;
    }

    public static void setTokenExtendedTableExist(boolean tokenExtendedTableExist) {

        OAuth2ServiceComponentHolder.tokenExtendedTableExist = tokenExtendedTableExist;
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

    public RealmService getRealmService() {

        return realmService;
    }

    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
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
     * Get the list of grant types which allowed JWT renew without revoke.
     *
     * @return JwtRenewWithoutRevokeAllowedGrantTypes
     */
    public static List<String> getJwtRenewWithoutRevokeAllowedGrantTypes() {

        return jwtRenewWithoutRevokeAllowedGrantTypes;
    }

    /**
     * Set the list of grant types which allowed JWT renew without revoke.
     *
     * @param jwtRenewWithoutRevokeAllowedGrantTypes List of grant types.
     */
    public static void setJwtRenewWithoutRevokeAllowedGrantTypes(
            List<String> jwtRenewWithoutRevokeAllowedGrantTypes) {

        OAuth2ServiceComponentHolder.jwtRenewWithoutRevokeAllowedGrantTypes =
                jwtRenewWithoutRevokeAllowedGrantTypes;
    }

    public static IdentityEventService getIdentityEventService() {

        return identityEventService;
    }

    public static void setIdentityEventService(IdentityEventService identityEventService) {
        OAuth2ServiceComponentHolder.identityEventService = identityEventService;
    }

    /**
     * Get Consent Server Configs Management Service.
     *
     * @return Consent Server Configs Management Service.
     */
    public static ConsentServerConfigsManagementService getConsentServerConfigsManagementService() {

        return OAuth2ServiceComponentHolder.consentServerConfigsManagementService;
    }

    /**
     * Set Consent Server Configs Management Service.
     *
     * @param consentServerConfigsManagementService Consent Server Configs Management Service.
     */
    public static void setConsentServerConfigsManagementService(ConsentServerConfigsManagementService
                                                                        consentServerConfigsManagementService) {

        OAuth2ServiceComponentHolder.consentServerConfigsManagementService = consentServerConfigsManagementService;
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

    public static boolean isRestrictUnassignedScopes() {

        return restrictUnassignedScopes;
    }

    public static void setRestrictUnassignedScopes(boolean restrictUnassignedScopes) {

        OAuth2ServiceComponentHolder.restrictUnassignedScopes = restrictUnassignedScopes;
    }

    public static ConfigurationContextService getConfigurationContextService() {

        return configurationContextService;
    }

    public static void setConfigurationContextService(ConfigurationContextService configurationContextService) {

        OAuth2ServiceComponentHolder.configurationContextService = configurationContextService;
    }

    /**
     * Get the OAuth2ScopeClaimMappingDAO instance.
     *
     * @param samlSSOServiceProviderManager SAMLSSOServiceProviderManager instance.
     */
    public static void setSamlSSOServiceProviderManager(SAMLSSOServiceProviderManager samlSSOServiceProviderManager) {

        OAuth2ServiceComponentHolder.samlSSOServiceProviderManager = samlSSOServiceProviderManager;
    }

    /**
     * Get the SAMLSSOServiceProviderManager instance.
     *
     * @return SAMLSSOServiceProviderManager instance.
     */
    public static SAMLSSOServiceProviderManager getSamlSSOServiceProviderManager() {

        return samlSSOServiceProviderManager;
    }

    /**
     * Returns JWT access token additional claim providers.
     *
     * @return
     */
    public List<JWTAccessTokenClaimProvider> getJWTAccessTokenClaimProviders() {

        return Collections.unmodifiableList(jwtAccessTokenClaimProviders);
    }

    public void addJWTAccessTokenClaimProvider(JWTAccessTokenClaimProvider accessTokenClaimProvider) {

        jwtAccessTokenClaimProviders.add(accessTokenClaimProvider);
    }

    public void removeJWTAccessTokenClaimProvider(JWTAccessTokenClaimProvider accessTokenClaimProvider) {

        jwtAccessTokenClaimProviders.add(accessTokenClaimProvider);
    }

    /**
     * Get whether organization management enabled.
     *
     * @return True if organization management is enabled.
     */
    public boolean isOrganizationManagementEnabled() {

        return isOrganizationManagementEnabled;
    }

    /**
     * Set organization management enable/disable state.
     *
     * @param organizationManagementInitializeService OrganizationManagementInitializeInstance.
     */
    public void setOrganizationManagementEnable(
            OrganizationManagementInitialize organizationManagementInitializeService) {

        if (organizationManagementInitializeService != null) {
            isOrganizationManagementEnabled = organizationManagementInitializeService.isOrganizationManagementEnabled();
        }
    }

    /**
     * Get the organization manager instance.
     *
     * @return OrganizationManager instance.
     */
    public OrganizationManager getOrganizationManager() {

        return organizationManager;
    }

    /**
     * Set the organization manager instance.
     *
     * @param organizationManager OrganizationManager instance.
     */
    public void setOrganizationManager(OrganizationManager organizationManager) {

        this.organizationManager = organizationManager;
    }

    /**
     * set ResponseModeProvider map
     */
    public static void setResponseModeProviders(Map<String, ResponseModeProvider> responseModeProvidersMap) {

        responseModeProviders = responseModeProvidersMap;
    }

    /**
     * set DefaultResponseModeProvider
     */
    public static void setDefaultResponseModeProvider(ResponseModeProvider responseModeProvider) {

        defaultResponseModeProvider = responseModeProvider;
    }

    /**
     * get DefaultResponseModeProvider
     */
    public static ResponseModeProvider getDefaultResponseModeProvider() {

        return defaultResponseModeProvider;
    }

    /**
     * This returns responseModeProviders map with all supported (configured) response modes and their providers
     * @return Map<String, ResponseModeProvider>
     */
    public static Map<String, ResponseModeProvider> getResponseModeProviders() {
        return responseModeProviders;
    }

    /**
     * Method to get the configured ResponseModeProvider implementation.
     *
     * @return the configured response mode provider for the Authorization response.
     */
    public static ResponseModeProvider getResponseModeProvider(String responseMode) {

        if (responseMode == null) {
            // if response mode is not provided, the DefaultResponseModeProvider is used
            return getDefaultResponseModeProvider();
        }
        ResponseModeProvider responseModeProvider = responseModeProviders.get(responseMode);
        if (responseModeProvider == null) {
            // if response mode is not in the configured response modes, the DefaultResponseModeProvider is used
            return getDefaultResponseModeProvider();
        }
        return responseModeProvider;
    }

    /**
     * Get the list of oauth authorization request builder implementations available.
     *
     * @return List<OAuthAuthorizationRequestBuilder> returns a list ot request builders.
     */
    public List<OAuthAuthorizationRequestBuilder> getAuthorizationRequestBuilders() {

        return oAuthAuthorizationRequestBuilders;
    }

    /**
     * Add request builder implementation.
     *
     * @param oAuthAuthorizationRequestBuilder Request builder implementation.
     */
    public void addAuthorizationRequestBuilder(OAuthAuthorizationRequestBuilder oAuthAuthorizationRequestBuilder) {

        oAuthAuthorizationRequestBuilders.add(oAuthAuthorizationRequestBuilder);
    }

    /**
     * Remove request builder implementation.
     *
     * @param oAuthAuthorizationRequestBuilder Request builder implementation.
     */
    public void removeAuthorizationRequestBuilder(OAuthAuthorizationRequestBuilder oAuthAuthorizationRequestBuilder) {

        oAuthAuthorizationRequestBuilders.remove(oAuthAuthorizationRequestBuilder);
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

    public AuthorizedAPIManagementService getAuthorizedAPIManagementService() {

        return authorizedAPIManagementService;
    }

    public void setAuthorizedAPIManagementService(AuthorizedAPIManagementService authorizedAPIManagementService) {

        this.authorizedAPIManagementService = authorizedAPIManagementService;
    }

    /**
     * Get APIResourceManager osgi service.
     *
     * @return APIResourceManager.
     */
    public APIResourceManager getApiResourceManager() {
        return apiResourceManager;
    }
    /**
     * Set APIResourceManager osgi service.
     *
     * @param apiResourceManager APIResourceManager.
     */
    public void setApiResourceManager(APIResourceManager apiResourceManager) {

        this.apiResourceManager = apiResourceManager;
    }

    /**
     * Get {@link RoleManagementService}.
     *
     * @return Instance of {@link RoleManagementService}.
     */
    public RoleManagementService getRoleManagementServiceV2() {

        return roleManagementServiceV2;
    }

    /**
     * Set {@link RoleManagementService}.
     *
     * @param roleManagementServiceV2 Instance of {@link RoleManagementService}.
     */
    public void setRoleManagementServiceV2(RoleManagementService roleManagementServiceV2) {

        this.roleManagementServiceV2 = roleManagementServiceV2;
    }
}
