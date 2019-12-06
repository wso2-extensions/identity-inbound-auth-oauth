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

import org.wso2.carbon.identity.application.authentication.framework.AuthenticationMethodNameTranslator;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.handler.HandlerComparator;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthenticator;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinder;
import org.wso2.carbon.identity.openidconnect.ClaimProvider;
import org.wso2.carbon.registry.core.service.RegistryService;

import java.util.ArrayList;
import java.util.List;
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
    private List<TokenBinder> tokenBinders = new ArrayList<>();
    private OAuthAdminServiceImpl oauthAdminService;

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

    public OAuthAdminServiceImpl getOAuthAdminService() {

        return oauthAdminService;
    }

    public void setOAuthAdminService(OAuthAdminServiceImpl oauthAdminService) {

        this.oauthAdminService = oauthAdminService;
    }
}
