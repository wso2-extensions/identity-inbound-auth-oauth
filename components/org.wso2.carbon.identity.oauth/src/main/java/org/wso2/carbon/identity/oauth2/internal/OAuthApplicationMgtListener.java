/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.mgt.listener.AbstractApplicationMgtListener;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthConsumerDAO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;

import java.util.HashSet;
import java.util.Set;

public class OAuthApplicationMgtListener extends AbstractApplicationMgtListener {
    public static final String OAUTH2 = "oauth2";
    public static final String OAUTH2_CONSUMER_SECRET = "oauthConsumerSecret";
    private static final String OAUTH = "oauth";
    private static final String SAAS_PROPERTY = "saasProperty";
    private static Log log = LogFactory.getLog(OAuthApplicationMgtListener.class);

    @Override
    public int getDefaultOrderId() {
        return 11;
    }

    public boolean doPreUpdateApplication(ServiceProvider serviceProvider, String tenantDomain, String userName)
            throws IdentityApplicationManagementException {
        storeSaaSPropertyValue(serviceProvider, tenantDomain);
        removeClientSecret(serviceProvider);
        return true;
    }

    public boolean doPostGetServiceProvider(ServiceProvider serviceProvider, String serviceProviderName, String tenantDomain)
            throws IdentityApplicationManagementException {
        addClientSecret(serviceProvider);
        return true;
    }

    public boolean doPostGetServiceProviderByClientId(ServiceProvider serviceProvider, String clientId, String clientType,
                                                      String tenantDomain) throws IdentityApplicationManagementException {
        addClientSecret(serviceProvider);
        return true;
    }

    public boolean doPostCreateApplication(ServiceProvider serviceProvider, String tenantDomain, String userName) throws IdentityApplicationManagementException {
        addClientSecret(serviceProvider);
        return true;
    }

    public boolean doPostUpdateApplication(ServiceProvider serviceProvider, String tenantDomain, String userName) throws IdentityApplicationManagementException {

        revokeAccessTokensWhenSaaSDisabled(serviceProvider, tenantDomain);
        addClientSecret(serviceProvider);
        updateAuthApplication(serviceProvider);
        if (OAuthServerConfiguration.getInstance().isCacheEnabled()) {
            removeEntriesFromCache(serviceProvider, tenantDomain, userName);
        }
        return true;
    }

    @Override
    public boolean doPostGetApplicationExcludingFileBasedSPs(ServiceProvider serviceProvider, String applicationName, String tenantDomain) throws IdentityApplicationManagementException {
        addClientSecret(serviceProvider);
        return true;
    }

    @Override
    public boolean doPreDeleteApplication(String applicationName, String tenantDomain, String userName) throws IdentityApplicationManagementException {
        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        ServiceProvider serviceProvider = applicationMgtService.getApplicationExcludingFileBasedSPs(applicationName, tenantDomain);
        if (OAuthServerConfiguration.getInstance().isCacheEnabled()) {
            removeEntriesFromCache(serviceProvider, tenantDomain, userName);
        }
        return true;
    }

    private void removeClientSecret(ServiceProvider serviceProvider) {
        InboundAuthenticationConfig inboundAuthenticationConfig = serviceProvider.getInboundAuthenticationConfig();
        if (inboundAuthenticationConfig != null) {
            InboundAuthenticationRequestConfig[] inboundRequestConfigs = inboundAuthenticationConfig.
                    getInboundAuthenticationRequestConfigs();
            if (inboundRequestConfigs != null) {
                for (InboundAuthenticationRequestConfig inboundRequestConfig : inboundRequestConfigs) {
                    if (inboundRequestConfig.getInboundAuthType().equals(OAUTH2)) {
                        Property[] props = inboundRequestConfig.getProperties();
                        for (Property prop : props) {
                            if (prop.getName().equalsIgnoreCase(OAUTH2_CONSUMER_SECRET)) {
                                props = (Property[]) ArrayUtils.removeElement(props, prop);
                                inboundRequestConfig.setProperties(props);
                                continue;   //we are interested only on this property
                            } else {
                                //ignore
                            }
                        }
                        continue;// we are interested only on oauth2 config. Only one will be present.
                    } else {
                        //ignore
                    }
                }
            } else {
                //ignore
            }
        } else {
            //nothing to do
        }
    }

    private void addClientSecret(ServiceProvider serviceProvider) throws IdentityApplicationManagementException {

        if (serviceProvider == null) {
            return; // if service provider is not present no need to add this information
        }

        try {
            InboundAuthenticationConfig inboundAuthenticationConfig = serviceProvider.getInboundAuthenticationConfig();
            if (inboundAuthenticationConfig != null) {
                InboundAuthenticationRequestConfig[] inboundRequestConfigs = inboundAuthenticationConfig.
                        getInboundAuthenticationRequestConfigs();
                if (inboundRequestConfigs != null) {
                    for (InboundAuthenticationRequestConfig inboundRequestConfig : inboundRequestConfigs) {
                        if (inboundRequestConfig.getInboundAuthType().equals(OAUTH2)) {
                            Property[] props = inboundRequestConfig.getProperties();
                            Property property = new Property();
                            property.setName(OAUTH2_CONSUMER_SECRET);
                            property.setValue(getClientSecret(inboundRequestConfig.getInboundAuthKey()));
                            props = (Property[]) ArrayUtils.add(props, property);
                            inboundRequestConfig.setProperties(props);
                            continue;// we are interested only on oauth2 config. Only one will be present.
                        } else {
                            //ignore
                        }
                    }
                } else {
                    //ignore
                }
            } else {
                //nothing to do
            }
        } catch (IdentityOAuthAdminException e) {
            throw new IdentityApplicationManagementException("Injecting client secret failed.", e);
        }


        return;
    }

    private String getClientSecret(String inboundAuthKey) throws IdentityOAuthAdminException {
        OAuthConsumerDAO dao = new OAuthConsumerDAO();
        return dao.getOAuthConsumerSecret(inboundAuthKey);
    }

    /**
     * Update the application name if OAuth application presents.
     *
     * @param serviceProvider Service provider
     * @throws IdentityApplicationManagementException
     */
    private void updateAuthApplication(ServiceProvider serviceProvider)
            throws IdentityApplicationManagementException {

        InboundAuthenticationRequestConfig authenticationRequestConfigConfig = null;
        if (serviceProvider.getInboundAuthenticationConfig() != null &&
                serviceProvider.getInboundAuthenticationConfig()
                        .getInboundAuthenticationRequestConfigs() != null) {

            for (InboundAuthenticationRequestConfig authConfig : serviceProvider.getInboundAuthenticationConfig()
                    .getInboundAuthenticationRequestConfigs()) {
                if (StringUtils.equals(authConfig.getInboundAuthType(), "oauth") ||
                        StringUtils.equals(authConfig.getInboundAuthType(), "oauth2")) {
                    authenticationRequestConfigConfig = authConfig;
                    break;
                }
            }
        }

        if (authenticationRequestConfigConfig == null) {
            return;
        }

        OAuthAppDAO dao = new OAuthAppDAO();
        dao.updateOAuthConsumerApp(serviceProvider.getApplicationName(),
                authenticationRequestConfigConfig.getInboundAuthKey());
    }

    private void removeEntriesFromCache(ServiceProvider serviceProvider, String tenantDomain, String userName)
            throws IdentityApplicationManagementException {
        TokenMgtDAO tokenMgtDAO = new TokenMgtDAO();
        Set<String> accessTokens = new HashSet<>();
        Set<String> authorizationCodes = new HashSet<>();
        Set<String> oauthKeys = new HashSet<>();
        try {
            InboundAuthenticationConfig inboundAuthenticationConfig = serviceProvider.getInboundAuthenticationConfig();
            if (inboundAuthenticationConfig != null) {
                InboundAuthenticationRequestConfig[] inboundRequestConfigs = inboundAuthenticationConfig.
                        getInboundAuthenticationRequestConfigs();
                if (inboundRequestConfigs != null) {
                    for (InboundAuthenticationRequestConfig inboundRequestConfig : inboundRequestConfigs) {
                        if (StringUtils.equals(OAUTH2, inboundRequestConfig.getInboundAuthType()) || StringUtils
                                .equals(inboundRequestConfig.getInboundAuthType(), OAUTH)) {
                            oauthKeys.add(inboundRequestConfig.getInboundAuthKey());
                        }
                    }
                }
            }
            if (oauthKeys.size() > 0) {
                AppInfoCache appInfoCache = AppInfoCache.getInstance();
                for (String oauthKey : oauthKeys) {
                    accessTokens.addAll(tokenMgtDAO.getActiveTokensForConsumerKey(oauthKey));
                    authorizationCodes.addAll(tokenMgtDAO.getAuthorizationCodesForConsumerKey(oauthKey));
                    // Remove client credential from AppInfoCache
                    appInfoCache.clearCacheEntry(oauthKey);
                }
            }
            if (accessTokens.size() > 0) {
                for (String accessToken : accessTokens) {
                    // Remove access token from AuthorizationGrantCache
                    AuthorizationGrantCacheKey grantCacheKey = new AuthorizationGrantCacheKey(accessToken);
                    AuthorizationGrantCacheEntry grantCacheEntry = (AuthorizationGrantCacheEntry) AuthorizationGrantCache
                            .getInstance().getValueFromCacheByToken(grantCacheKey);
                    if (grantCacheEntry != null) {
                        AuthorizationGrantCache.getInstance().clearCacheEntryByToken(grantCacheKey);
                    }

                    // Remove access token from OAuthCache
                    OAuthCacheKey oauthCacheKey = new OAuthCacheKey(accessToken);
                    CacheEntry oauthCacheEntry = OAuthCache.getInstance().getValueFromCache(oauthCacheKey);
                    if (oauthCacheEntry != null) {
                        OAuthCache.getInstance().clearCacheEntry(oauthCacheKey);
                    }
                }
            }

            if (authorizationCodes.size() > 0) {
                for (String authorizationCode : authorizationCodes) {
                    // Remove authorization code from AuthorizationGrantCache
                    AuthorizationGrantCacheKey grantCacheKey = new AuthorizationGrantCacheKey(authorizationCode);
                    AuthorizationGrantCacheEntry grantCacheEntry = (AuthorizationGrantCacheEntry) AuthorizationGrantCache
                            .getInstance().getValueFromCacheByToken(grantCacheKey);
                    if (grantCacheEntry != null) {
                        AuthorizationGrantCache.getInstance().clearCacheEntryByCode(grantCacheKey);
                    }

                    // Remove authorization code from OAuthCache
                    OAuthCacheKey oauthCacheKey = new OAuthCacheKey(authorizationCode);
                    CacheEntry oauthCacheEntry = OAuthCache.getInstance().getValueFromCache(oauthCacheKey);
                    if (oauthCacheEntry != null) {
                        OAuthCache.getInstance().clearCacheEntry(oauthCacheKey);
                    }
                }
            }
        } catch (IdentityOAuth2Exception e) {
            throw new IdentityApplicationManagementException("Error occurred when removing oauth cache entries upon " +
                    "service provider update. ", e);
        }

    }

    /**
     * Stores the value of SaaS property before application is updated.
     *
     * @param serviceProvider Service Provider
     * @param tenantDomain    Application tenant domain
     * @throws IdentityApplicationManagementException
     */
    private void storeSaaSPropertyValue(ServiceProvider serviceProvider, String tenantDomain) throws IdentityApplicationManagementException {

        ServiceProvider sp = OAuth2ServiceComponentHolder.getApplicationMgtService()
                .getServiceProvider(serviceProvider.getApplicationName(), tenantDomain);
        IdentityUtil.threadLocalProperties.get().put(SAAS_PROPERTY, sp.isSaasApp());
    }

    /**
     * Revokes access tokens of OAuth applications if SaaS is disabled.
     *
     * @param serviceProvider Service Provider
     * @param tenantDomain    Application tenant domain
     * @throws IdentityApplicationManagementException
     */
    private void revokeAccessTokensWhenSaaSDisabled(final ServiceProvider serviceProvider, final String tenantDomain) throws IdentityApplicationManagementException {

        try {
            boolean wasSaasEnabled = false;
            Object saasStatus = IdentityUtil.threadLocalProperties.get().get(SAAS_PROPERTY);
            if (saasStatus instanceof Boolean) {
                wasSaasEnabled = (Boolean) saasStatus;
            }
            if (wasSaasEnabled && !serviceProvider.isSaasApp()) {
                if (log.isDebugEnabled()) {
                    log.debug("SaaS setting removed for application: " + serviceProvider.getApplicationName()
                            + "in tenant domain: " + tenantDomain + ", hence proceeding to token revocation of other tenants.");
                }
                final int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
                final TokenMgtDAO tokenMgtDAO = new TokenMgtDAO();

                new Thread(new Runnable() {
                    public void run() {
                        InboundAuthenticationRequestConfig[] configs = serviceProvider.getInboundAuthenticationConfig()
                                .getInboundAuthenticationRequestConfigs();
                        for (InboundAuthenticationRequestConfig config : configs) {
                            if (IdentityApplicationConstants.OAuth2.NAME.equalsIgnoreCase(config.getInboundAuthType()) &&
                                    config.getInboundAuthKey() != null) {
                                String oauthKey = config.getInboundAuthKey();
                                try {
                                    tokenMgtDAO.revokeSaaSTokensOfOtherTenants(oauthKey, tenantId);
                                } catch (IdentityOAuth2Exception e) {
                                    log.error("Error occurred while revoking access tokens for client ID: "
                                            + config.getInboundAuthKey() + " and tenant domain: " + tenantDomain, e);
                                }
                            }
                        }
                    }
                }).start();
            }
        } finally {
            IdentityUtil.threadLocalProperties.get().remove(SAAS_PROPERTY);
        }
    }
}
