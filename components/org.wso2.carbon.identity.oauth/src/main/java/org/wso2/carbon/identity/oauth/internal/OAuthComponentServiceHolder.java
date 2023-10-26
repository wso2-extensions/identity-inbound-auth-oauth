/*
 * Copyright (c) 2013-2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.oauth.common.token.bindings.TokenBinderInfo;
import org.wso2.carbon.identity.oauth.dto.TokenBindingMetaDataDTO;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.listener.OAuthApplicationMgtListener;
import org.wso2.carbon.identity.oauth2.OAuth2ScopeService;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAO;
import org.wso2.carbon.identity.oauth2.dao.TokenManagementDAO;
import org.wso2.carbon.identity.oauth2.token.handlers.response.AccessTokenResponseHandler;
import org.wso2.carbon.identity.oauth2.validators.scope.ScopeValidator;
import org.wso2.carbon.identity.oauth2.validators.validationhandler.ScopeValidationHandler;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.OrganizationUserResidentResolverService;
import org.wso2.carbon.identity.role.mgt.core.RoleManagementService;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Data holder for OAuth component.
 */
public class OAuthComponentServiceHolder {

    private static OAuthComponentServiceHolder instance = new OAuthComponentServiceHolder();
    private RealmService realmService;
    private OAuthEventInterceptor oAuthEventInterceptorHandlerProxy;
    private OAuth2Service oauth2Service;
    private static final Log log = LogFactory.getLog(OAuthComponentServiceHolder.class);
    private OAuth2ScopeService oauth2ScopeService;
    private List<TokenBindingMetaDataDTO> tokenBindingMetaDataDTOs = new ArrayList<>();
    private OAuthAdminServiceImpl oAuthAdminService;
    private List<ScopeValidator> scopeValidators = new ArrayList<>();
    private List<ScopeValidationHandler> scopeValidationHandlers = new ArrayList<>();
    private Map<Integer, OAuthApplicationMgtListener> oAuthApplicationMgtListeners = new TreeMap<>();
    private RoleManagementService roleManagementService;
    private OrganizationUserResidentResolverService organizationUserResidentResolverService;
    private OrganizationManager organizationManager;
    private List<AccessTokenResponseHandler> accessTokenResponseHandlers = new ArrayList<>();
    private AccessTokenDAO accessTokenDAOService;
    private TokenManagementDAO tokenManagementDAOService;

    /**
     * Get the list of scope validator implementations available.
     *
     * @return ScopeValidaror returns a list ot scope validator.
     */
    public List<ScopeValidator> getScopeValidators() {

        return scopeValidators;
    }

    /**
     * Add scope validator implementation.
     *
     * @param scopeValidator Scope validator implementation.
     */
    public void addScopeValidator(ScopeValidator scopeValidator) {

        scopeValidators.add(scopeValidator);
    }

    /**
     * Remove scope validator implementation.
     *
     * @param scopeValidator Scope validator implementation.
     */
    public void removeScopeValidator(ScopeValidator scopeValidator) {

        scopeValidators.remove(scopeValidator);
    }

    /**
     * Set a list of scope validator implementations.
     *
     * @param scopeValidators List of Scope validator implementation.
     */
    public void setScopeValidators(List<ScopeValidator> scopeValidators) {

        this.scopeValidators = scopeValidators;
    }

    /**
     * Get the list of scope validation handler implementations available.
     *
     * @return ScopeValidationHandler returns a list ot scope validation policy handler.
     */
    public List<ScopeValidationHandler> getScopeValidationHandlers() {

        return scopeValidationHandlers;
    }

    /**
     * Add scope validation handler implementation.
     *
     * @param scopeValidationHandler Scope validation handler implementation.
     */
    public void addScopeValidationHandler(ScopeValidationHandler scopeValidationHandler) {

        scopeValidationHandlers.add(scopeValidationHandler);
    }

    /**
     * Remove scope validation policy implementation.
     *
     * @param scopeValidationHandler Scope validation policy implementation.
     */
    public void removeScopeValidationHandler(ScopeValidationHandler scopeValidationHandler) {

        scopeValidationHandlers.remove(scopeValidationHandler);
    }

    /**
     * Set a list of scope validation handler implementations.
     *
     * @param scopeValidationHandlers List of Scope validation handler implementation.
     */
    public void setScopeValidatorPolicyHandlers(List<ScopeValidationHandler> scopeValidationHandlers) {

        this.scopeValidationHandlers = scopeValidationHandlers;
    }

    private OAuthComponentServiceHolder() {

    }

    public static OAuthComponentServiceHolder getInstance() {

        return instance;
    }

    public RealmService getRealmService() {

        return realmService;
    }

    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    public void addOauthEventInterceptorProxy(OAuthEventInterceptor oAuthEventInterceptorHandlerProxy) {
        this.oAuthEventInterceptorHandlerProxy = oAuthEventInterceptorHandlerProxy;
    }

    public OAuthEventInterceptor getOAuthEventInterceptorProxy() {
        return this.oAuthEventInterceptorHandlerProxy;
    }

    public OAuth2Service getOauth2Service() {
        return oauth2Service;
    }

    public void setOauth2Service(OAuth2Service oauth2Service) {
        this.oauth2Service = oauth2Service;
    }

    public OAuth2ScopeService getOauth2ScopeService() {

        return oauth2ScopeService;
    }

    public void setOauth2ScopeService(OAuth2ScopeService oauth2ScopeService) {

        this.oauth2ScopeService = oauth2ScopeService;
    }

    public List<TokenBindingMetaDataDTO> getTokenBindingMetaDataDTOs() {

        return tokenBindingMetaDataDTOs;
    }

    public void addTokenBinderInfo(TokenBinderInfo tokenBinderInfo) {

        tokenBindingMetaDataDTOs
                .add(new TokenBindingMetaDataDTO(tokenBinderInfo.getDisplayName(), tokenBinderInfo.getDescription(),
                        tokenBinderInfo.getBindingType(), tokenBinderInfo.getSupportedGrantTypes()));
    }

    public void removeTokenBinderInfo(TokenBinderInfo tokenBinderInfo) {

        tokenBindingMetaDataDTOs.removeIf(tokenBindingMetaDataDTO -> tokenBinderInfo.getBindingType()
                .equals(tokenBindingMetaDataDTO.getTokenBindingType()));
    }

    public OAuthAdminServiceImpl getoAuthAdminService() {

        return oAuthAdminService;
    }

    public void setOAuthAdminService(OAuthAdminServiceImpl oAuthAdminService) {

        this.oAuthAdminService = oAuthAdminService;
    }

    public Collection<OAuthApplicationMgtListener> getOAuthApplicationMgtListeners() {

        if (oAuthApplicationMgtListeners.isEmpty()) {
            return Collections.emptyList();
        }
        return oAuthApplicationMgtListeners.values();
    }

    public void addOAuthApplicationMgtListener(OAuthApplicationMgtListener oAuthApplicationMgtListener) {

        this.oAuthApplicationMgtListeners
                .put(oAuthApplicationMgtListener.getExecutionOrder(), oAuthApplicationMgtListener);
    }

    public void removeOAuthApplicationMgtListener(OAuthApplicationMgtListener oAuthApplicationMgtListener) {

        this.oAuthApplicationMgtListeners
                .remove(oAuthApplicationMgtListener.getExecutionOrder(), oAuthApplicationMgtListener);
    }

    /**
     * Set RoleManagementService instance.
     *
     * @param roleManagementService RoleManagementService instance.
     */
    public void setRoleManagementService(RoleManagementService roleManagementService) {

        this.roleManagementService = roleManagementService;
    }

    /**
     * Get RoleManagementService instance.
     *
     * @return RoleManagementService instance.
     */
    public RoleManagementService getRoleManagementService() {

        return roleManagementService;
    }

    /**
     * Get OrganizationUserResidentResolverService instance.
     *
     * @return OrganizationUserResidentResolverService instance.
     */
    public OrganizationUserResidentResolverService getOrganizationUserResidentResolverService() {

        return organizationUserResidentResolverService;
    }

    /**
     * Set OrganizationUserResidentResolverService instance.
     *
     * @param organizationUserResidentResolverService OrganizationUserResidentResolverService instance.
     */
    public void setOrganizationUserResidentResolverService(
            OrganizationUserResidentResolverService organizationUserResidentResolverService) {

        this.organizationUserResidentResolverService = organizationUserResidentResolverService;
    }

    /**
     * Get OrganizationManager instance.
     *
     * @return OrganizationManager instance.
     */
    public OrganizationManager getOrganizationManager() {

        return organizationManager;
    }

    /**
     * Set OrganizationManager instance.
     *
     * @param organizationManager OrganizationManager instance.
     */
    public void setOrganizationManager(OrganizationManager organizationManager) {

        this.organizationManager = organizationManager;
    }

    /**
     * Registers access token response handlers for modifying token response attributes.
     *
     * @param accessTokenResponseHandler {@link AccessTokenResponseHandler} instance.
     */
    public void addAccessTokenResponseHandler(AccessTokenResponseHandler accessTokenResponseHandler) {

        accessTokenResponseHandlers.add(accessTokenResponseHandler);
    }

    /**
     * Removes access token response handlers registered.
     *
     * @param accessTokenResponseHandler {@link AccessTokenResponseHandler} instance.
     */
    public void removeAccessTokenResponseHandler(AccessTokenResponseHandler accessTokenResponseHandler) {

        accessTokenResponseHandlers.remove(accessTokenResponseHandler);
    }

    /**
     * Returns all the access token response handlers registered.
     *
     * @return List of {@link AccessTokenResponseHandler}.
     */
    public List<AccessTokenResponseHandler> getAccessTokenResponseHandlers() {

        return accessTokenResponseHandlers;
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
}
