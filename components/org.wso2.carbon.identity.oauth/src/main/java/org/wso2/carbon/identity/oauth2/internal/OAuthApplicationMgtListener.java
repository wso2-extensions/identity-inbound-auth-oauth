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
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.StandardInboundProtocols;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementClientException;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementServerException;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementValidationException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.mgt.listener.AbstractApplicationMgtListener;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.IdentityOAuthClientException;
import org.wso2.carbon.identity.oauth.OAuthAdminService;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import static org.apache.commons.collections.CollectionUtils.isNotEmpty;

/**
 * Application management listener for OAuth related functionality.
 */
public class OAuthApplicationMgtListener extends AbstractApplicationMgtListener {
    public static final String OAUTH2 = "oauth2";
    public static final String OAUTH2_CONSUMER_SECRET = "oauthConsumerSecret";
    private static final String OAUTH = "oauth";
    private static final String SAAS_PROPERTY = "saasProperty";
    private static final Log log = LogFactory.getLog(OAuthApplicationMgtListener.class);

    @Override
    public int getDefaultOrderId() {
        // Since we are deleting OAuth app data in pre delete operation, we want this listener to be executed as
        // late as possible allowing other listeners to execute and break the flow if required.
        return 901;
    }

    public boolean doPreUpdateApplication(ServiceProvider serviceProvider, String tenantDomain, String userName)
            throws IdentityApplicationManagementException {

        handleOAuthAppAssociationRemoval(serviceProvider);
        storeSaaSPropertyValue(serviceProvider);
        removeClientSecret(serviceProvider);
        return true;
    }

    public boolean doPostGetServiceProvider(ServiceProvider serviceProvider, String serviceProviderName,
                                            String tenantDomain)
            throws IdentityApplicationManagementException {

        addClientSecret(serviceProvider);
        return true;
    }

    public boolean doPostGetServiceProviderByClientId(ServiceProvider serviceProvider, String clientId,
                                                      String clientType, String tenantDomain)
            throws IdentityApplicationManagementException {

        addClientSecret(serviceProvider);
        return true;
    }

    public boolean doPostCreateApplication(ServiceProvider serviceProvider, String tenantDomain, String userName)
            throws IdentityApplicationManagementException {

        addClientSecret(serviceProvider);
        return true;
    }

    public boolean doPostUpdateApplication(ServiceProvider serviceProvider, String tenantDomain, String userName)
            throws IdentityApplicationManagementException {

        revokeAccessTokensWhenSaaSDisabled(serviceProvider, tenantDomain);
        addClientSecret(serviceProvider);
        updateAuthApplication(serviceProvider);
        removeEntriesFromCache(serviceProvider, tenantDomain);
        return true;
    }

    @Override
    public boolean doPostGetApplicationExcludingFileBasedSPs(ServiceProvider serviceProvider, String applicationName,
                                                             String tenantDomain)
            throws IdentityApplicationManagementException {

        addClientSecret(serviceProvider);
        return true;
    }

    @Override
    public boolean doPreDeleteApplication(String applicationName,
                                          String tenantDomain,
                                          String userName) throws IdentityApplicationManagementException {

        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        ServiceProvider serviceProvider = applicationMgtService.getApplicationExcludingFileBasedSPs(applicationName,
                tenantDomain);
        if (serviceProvider != null) {
            try {
                if (log.isDebugEnabled()) {
                    log.debug("Deleting OAuth inbound data associated with application: " + applicationName
                            + " in tenantDomain: " + tenantDomain + " during application delete.");
                }
                deleteAssociatedOAuthApps(serviceProvider, tenantDomain);
            } catch (IdentityOAuthAdminException | IdentityOAuth2Exception e) {
                throw new IdentityApplicationManagementException("Error while cleaning up oauth application data " +
                        "associated with service provider: " + applicationName + " of tenantDomain: " + tenantDomain,
                        e);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Service Provider not found with name: " + applicationName);
            }
        }
        return true;
    }

    private Set<String> getOAuthAppsAssociatedWithApplication(ServiceProvider serviceProvider) {

        Set<String> oauthKeys = new HashSet<>();
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

        return oauthKeys;
    }

    private void deleteAssociatedOAuthApps(ServiceProvider serviceProvider, String tenantDomain)
            throws IdentityOAuthAdminException, IdentityOAuth2Exception {

        Set<String> associatedOAuthConsumerKeys = getOAuthAppsAssociatedWithApplication(serviceProvider);
        for (String consumerKey : associatedOAuthConsumerKeys) {
            if (log.isDebugEnabled()) {
                log.debug("Removing OAuth application data for clientId: " + consumerKey + " associated with " +
                        "application: " + serviceProvider.getApplicationName() + " tenantDomain: " + tenantDomain);
            }
            OAuth2ServiceComponentHolder.getInstance().getOAuthAdminService().removeOAuthApplicationData(consumerKey);
        }
        removeEntriesFromCache(associatedOAuthConsumerKeys);
    }

    public void onPreCreateInbound(ServiceProvider serviceProvider, boolean isUpdate) throws
            IdentityApplicationManagementException {

        validateOAuthInbound(serviceProvider, isUpdate);
    }

    @Override
    public void doImportServiceProvider(ServiceProvider serviceProvider) throws IdentityApplicationManagementException {

        try {
            if (serviceProvider.getInboundAuthenticationConfig() != null &&
                    serviceProvider.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs() != null) {

                for (InboundAuthenticationRequestConfig authConfig : serviceProvider.getInboundAuthenticationConfig()
                        .getInboundAuthenticationRequestConfigs()) {
                    if (OAUTH.equals(authConfig.getInboundAuthType()) ||
                            OAUTH2.equals(authConfig.getInboundAuthType())) {
                        String inboundConfiguration = authConfig.getInboundConfiguration();
                        if (inboundConfiguration == null || "".equals(inboundConfiguration)) {
                            String errorMSg = String.format("No inbound configurations found for oauth in the " +
                                            "imported %s", serviceProvider.getApplicationName());
                            throw new IdentityApplicationManagementException(errorMSg);
                        }
                        User owner = serviceProvider.getOwner();
                        OAuthAppDO oAuthAppDO = marshelOAuthDO(authConfig.getInboundConfiguration(),
                                serviceProvider.getApplicationName(), owner.getTenantDomain());
                        oAuthAppDO.setAppOwner(new AuthenticatedUser(owner));

                        OAuthConsumerAppDTO oAuthConsumerAppDTO = OAuthUtil.buildConsumerAppDTO(oAuthAppDO);
                        OAuthAppDAO dao = new OAuthAppDAO();

                        String oauthConsumerKey = oAuthConsumerAppDTO.getOauthConsumerKey();
                        boolean isExistingClient = dao.isDuplicateConsumer(oauthConsumerKey);

                        // Set the client secret before doing registering/updating the oauth app.
                        if (oAuthConsumerAppDTO.getOauthConsumerSecret() == null) {
                            if (isExistingClient) {
                                // For existing client, we fetch the existing client secret and set.
                                OAuthAppDO app = OAuth2Util.getAppInformationByClientId(oauthConsumerKey);
                                oAuthConsumerAppDTO.setOauthConsumerSecret(app.getOauthConsumerSecret());
                            } else {
                                oAuthConsumerAppDTO.setOauthConsumerSecret(OAuthUtil.getRandomNumber());
                            }
                        }

                        OAuthAdminServiceImpl oAuthAdminService =
                                OAuthComponentServiceHolder.getInstance().getoAuthAdminService();
                        if (isExistingClient) {
                            oAuthAdminService.updateConsumerApplication(oAuthConsumerAppDTO);
                        } else {
                            oAuthAdminService.registerOAuthApplicationData(oAuthConsumerAppDTO);
                        }
                        return;
                    }
                }
            }
        } catch (IdentityOAuthAdminException | InvalidOAuthClientException | IdentityOAuth2Exception e) {
            String message = "Error occurred when importing OAuth inbound.";
            throw handleException(message, e);
        }
    }

    private IdentityApplicationManagementException handleException(String message, Exception ex) {

        if (ex instanceof IdentityOAuthClientException || ex instanceof InvalidOAuthClientException) {
            return new IdentityApplicationManagementClientException(message, ex);
        } else {
            return new IdentityApplicationManagementServerException(message, ex);
        }
    }

    @Override
    public void doExportServiceProvider(ServiceProvider serviceProvider, Boolean exportSecrets)
            throws IdentityApplicationManagementException {

        try {
            if (serviceProvider.getInboundAuthenticationConfig() != null &&
                    serviceProvider.getInboundAuthenticationConfig()
                            .getInboundAuthenticationRequestConfigs() != null) {

                for (InboundAuthenticationRequestConfig authConfig : serviceProvider.getInboundAuthenticationConfig()
                        .getInboundAuthenticationRequestConfigs()) {
                    if (OAUTH.equals(authConfig.getInboundAuthType()) ||
                            OAUTH2.equals(authConfig.getInboundAuthType())) {

                        OAuthAppDAO dao = new OAuthAppDAO();
                        OAuthAppDO authApplication = dao.getAppInformation(authConfig.getInboundAuthKey());
                        String tokenProcessorName = OAuthServerConfiguration.getInstance().getPersistenceProcessor()
                                .getClass().getName();
                        if (!"org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor"
                                .equals(tokenProcessorName) || !exportSecrets) {
                            authApplication.setOauthConsumerSecret(null);
                        }

                        Property[] properties = authConfig.getProperties();
                        authConfig.setProperties(Arrays.stream(properties).filter(property ->
                                !"oauthConsumerSecret".equals(property.getName())).toArray(Property[]::new));

                        authConfig.setInboundConfiguration(unmarshelOAuthDO(authApplication));
                        return;
                    }
                }
            }
        } catch (InvalidOAuthClientException | IdentityOAuth2Exception e) {
            throw new IdentityApplicationManagementException("Error occurred when retrieving OAuth application ", e);
        }
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
                        continue; // we are interested only on oauth2 config. Only one will be present.
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
                            String clientSecret = null;
                            try {
                                clientSecret = OAuth2Util.getClientSecret(inboundRequestConfig.getInboundAuthKey());
                            } catch (InvalidOAuthClientException e) {
                                log.warn("The OAuth application data not exists for " +
                                        inboundRequestConfig.getInboundAuthKey());
                            }
                            property.setValue(clientSecret);
                            props = (Property[]) ArrayUtils.add(props, property);
                            inboundRequestConfig.setProperties(props);
                            continue; // we are interested only on oauth2 config. Only one will be present.
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
        } catch (IdentityOAuth2Exception e) {
            throw new IdentityApplicationManagementException("Injecting client secret failed.", e);
        }

        return;
    }

    /**
     * Update the application name and owner if OAuth application presents.
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
        try {
            dao.updateOAuthConsumerApp(serviceProvider, authenticationRequestConfigConfig.getInboundAuthKey());
        } catch (IdentityOAuthAdminException e) {
            throw new IdentityApplicationManagementException("Error occurred while updating oauth consumer app.", e);
        }
    }

    private void removeEntriesFromCache(Set<String> consumerKeys) throws IdentityOAuth2Exception {



        if (isNotEmpty(consumerKeys)) {
            Set<AccessTokenDO> accessTokenDOSet = new HashSet<>();
            Set<AuthzCodeDO> authzCodeDOSet = new HashSet<>();

            AppInfoCache appInfoCache = AppInfoCache.getInstance();
            for (String oauthKey : consumerKeys) {
                accessTokenDOSet.addAll(OAuthTokenPersistenceFactory.getInstance()
                        .getAccessTokenDAO().getActiveTokenSetWithTokenIdByConsumerKeyForOpenidScope(oauthKey));
                authzCodeDOSet.addAll(OAuthTokenPersistenceFactory.getInstance()
                        .getAuthorizationCodeDAO().getAuthorizationCodeDOSetByConsumerKeyForOpenidScope(oauthKey));
                // Remove client credential from AppInfoCache
                appInfoCache.clearCacheEntry(oauthKey);
                OAuthCache.getInstance().clearCacheEntry(new OAuthCacheKey(oauthKey));
            }

            if (isNotEmpty(accessTokenDOSet)) {
                clearCacheEntriesAgainstToken(accessTokenDOSet);
            }

            if (isNotEmpty(authzCodeDOSet)) {
                clearCacheEntriesAgainstAuthzCode(authzCodeDOSet);
            }
        }
    }

    private void removeEntriesFromCache(ServiceProvider serviceProvider,
                                        String tenantDomain) throws IdentityApplicationManagementException {

        Set<String> consumerKeys = getOAuthAppsAssociatedWithApplication(serviceProvider);
        try {
            removeEntriesFromCache(consumerKeys);
        } catch (IdentityOAuth2Exception e) {
            String applicationName = serviceProvider.getApplicationName();
            throw new IdentityApplicationManagementException("Error while clearing cache for oauth application data " +
                    "associated with service provider: " + applicationName + " of tenantDomain: " + tenantDomain, e);
        }
    }

    private void clearCacheEntriesAgainstAuthzCode(Set<AuthzCodeDO> authzCodeDOSet) {

        for (AuthzCodeDO authzCodeDO : authzCodeDOSet) {
            // Remove authorization code from AuthorizationGrantCache
            AuthorizationGrantCacheKey grantCacheKey = new AuthorizationGrantCacheKey(
                    authzCodeDO.getAuthorizationCode());
            AuthorizationGrantCache.getInstance()
                    .clearCacheEntryByCodeId(grantCacheKey, authzCodeDO.getAuthzCodeId());
            // Remove authorization code from OAuthCache
            OAuthCacheKey oauthCacheKey = new OAuthCacheKey(authzCodeDO.getAuthorizationCode());
            CacheEntry oauthCacheEntry = OAuthCache.getInstance().getValueFromCache(oauthCacheKey);
            if (oauthCacheEntry != null) {
                OAuthCache.getInstance().clearCacheEntry(oauthCacheKey);
            }
        }
    }

    private void clearCacheEntriesAgainstToken(Set<AccessTokenDO> accessTokenDOSet) {

        for (AccessTokenDO accessTokenDo : accessTokenDOSet) {
            // Remove access token from AuthorizationGrantCache
            AuthorizationGrantCacheKey grantCacheKey = new AuthorizationGrantCacheKey(
                    accessTokenDo.getAccessToken());
            AuthorizationGrantCache.getInstance()
                    .clearCacheEntryByTokenId(grantCacheKey, accessTokenDo.getTokenId());
            // Remove access token from OAuthCache
            OAuthCacheKey oauthCacheKey = new OAuthCacheKey(accessTokenDo.getAccessToken());
            CacheEntry oauthCacheEntry = OAuthCache.getInstance().getValueFromCache(oauthCacheKey);
            if (oauthCacheEntry != null) {
                OAuthCache.getInstance().clearCacheEntry(oauthCacheKey);
            }
        }
    }

    /**
     * Stores the value of SaaS property before application is updated.
     *
     * @param serviceProvider Service Provider
     * @throws IdentityApplicationManagementException
     */
    private void storeSaaSPropertyValue(ServiceProvider serviceProvider) throws IdentityApplicationManagementException {

        ServiceProvider sp = OAuth2ServiceComponentHolder.getApplicationMgtService()
                .getServiceProvider(serviceProvider.getApplicationID());
        IdentityUtil.threadLocalProperties.get().put(SAAS_PROPERTY, sp.isSaasApp());
    }

    private void handleOAuthAppAssociationRemoval(ServiceProvider updatedSp)
            throws IdentityApplicationManagementException {

        // Get the stored app.
        int appId = updatedSp.getApplicationID();

        ServiceProvider storedSp = OAuth2ServiceComponentHolder.getApplicationMgtService().getServiceProvider(appId);

        InboundAuthenticationRequestConfig storedOAuthConfig = getOAuthInbound(storedSp);
        InboundAuthenticationRequestConfig updatedOAuthInboundConfig = getOAuthInbound(updatedSp);

        if (isOAuthInboundAssociationRemoved(storedOAuthConfig, updatedOAuthInboundConfig)) {
            // Remove OAuth app data.
            String deletedConsumerKey = storedOAuthConfig.getInboundAuthKey();
            try {
                if (log.isDebugEnabled()) {
                    log.debug("OAuth inbound with clientId: " + deletedConsumerKey + " has been removed from " +
                            "service provider with id: " + appId + ". Removing the stale OAuth application for " +
                            "clientId: " + deletedConsumerKey);
                }
                OAuth2ServiceComponentHolder.getInstance()
                        .getOAuthAdminService().removeOAuthApplicationData(deletedConsumerKey);
            } catch (IdentityOAuthAdminException e) {
                String msg = "Error removing OAuth2 inbound data for clientId: %s associated with service provider " +
                        "with id: %s during application update.";
                throw new IdentityApplicationManagementException(String.format(msg, deletedConsumerKey, appId), e);
            }
        }
    }

    private boolean isOAuthInboundAssociationRemoved(InboundAuthenticationRequestConfig storedOAuthConfig,
                                                     InboundAuthenticationRequestConfig updatedOAuthInboundConfig) {

        return storedOAuthConfig != null && updatedOAuthInboundConfig == null;
    }

    private InboundAuthenticationRequestConfig getOAuthInbound(ServiceProvider sp) {

        if (sp != null && sp.getInboundAuthenticationConfig() != null) {
            if (ArrayUtils.isNotEmpty(sp.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs())) {
                return Arrays.stream(sp.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs())
                        .filter(inbound -> StandardInboundProtocols.OAUTH2.equals(inbound.getInboundAuthType()))
                        .findAny()
                        .orElse(null);
            }
        }

        return null;
    }

    /**
     * Revokes access tokens of OAuth applications if SaaS is disabled.
     *
     * @param serviceProvider Service Provider
     * @param tenantDomain    Application tenant domain
     */
    private void revokeAccessTokensWhenSaaSDisabled(final ServiceProvider serviceProvider, final String tenantDomain) {

        try {
            boolean wasSaasEnabled = false;
            Object saasStatus = IdentityUtil.threadLocalProperties.get().get(SAAS_PROPERTY);
            if (saasStatus instanceof Boolean) {
                wasSaasEnabled = (Boolean) saasStatus;
            }
            if (wasSaasEnabled && !serviceProvider.isSaasApp()) {
                if (log.isDebugEnabled()) {
                    log.debug("SaaS setting removed for application: " + serviceProvider.getApplicationName()
                            + "in tenant domain: " + tenantDomain +
                            ", hence proceeding to token revocation of other tenants.");
                }
                final int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

                new Thread(() -> {
                    InboundAuthenticationRequestConfig[] configs = serviceProvider.getInboundAuthenticationConfig()
                            .getInboundAuthenticationRequestConfigs();
                    for (InboundAuthenticationRequestConfig config : configs) {
                        if (IdentityApplicationConstants.OAuth2.NAME
                                .equalsIgnoreCase(config.getInboundAuthType()) &&
                                config.getInboundAuthKey() != null) {
                            String oauthKey = config.getInboundAuthKey();
                            try {
                                OAuthTokenPersistenceFactory.getInstance().getTokenManagementDAO()
                                        .revokeSaaSTokensOfOtherTenants(oauthKey, tenantId);
                            } catch (IdentityOAuth2Exception e) {
                                log.error("Error occurred while revoking access tokens for client ID: "
                                        + config.getInboundAuthKey() + " and tenant domain: " + tenantDomain, e);
                            }
                        }
                    }
                }).start();
            }
        } finally {
            IdentityUtil.threadLocalProperties.get().remove(SAAS_PROPERTY);
        }
    }

    /**
     * Validate Oauth inbound config.
     *
     * @param serviceProvider service provider.
     * @param isUpdate        whether the application update or create
     * @throws IdentityApplicationManagementValidationException Identity Application Management Exception
     */
    private void validateOAuthInbound(ServiceProvider serviceProvider, boolean isUpdate) throws
            IdentityApplicationManagementValidationException {

        List<String> validationMsg = new ArrayList<>();

        if (serviceProvider.getInboundAuthenticationConfig() != null &&
                serviceProvider.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs() != null) {

            for (InboundAuthenticationRequestConfig authConfig : serviceProvider.getInboundAuthenticationConfig()
                    .getInboundAuthenticationRequestConfigs()) {
                if (OAUTH.equals(authConfig.getInboundAuthType()) || OAUTH2.equals(authConfig.getInboundAuthType())) {
                    String inboundConfiguration = authConfig.getInboundConfiguration();
                    if (inboundConfiguration == null) {
                        return;
                    }
                    String inboundAuthKey = authConfig.getInboundAuthKey();
                    OAuthAppDAO dao = new OAuthAppDAO();
                    OAuthAppDO oAuthAppDO;

                    String tenantDomain = serviceProvider.getOwner().getTenantDomain();
                    String userName = serviceProvider.getOwner().getUserName();

                    try {
                        oAuthAppDO = marshelOAuthDO(inboundConfiguration,
                                serviceProvider.getApplicationName(), tenantDomain);
                    } catch (IdentityApplicationManagementException e) {
                        validationMsg.add("OAuth inbound configuration in the file is not valid.");
                        break;
                    }
                    if (!inboundAuthKey.equals(oAuthAppDO.getOauthConsumerKey())) {
                        validationMsg.add(String.format("The Inbound Auth Key of the  application name %s " +
                                        "is not match with Oauth Consumer Key %s.", authConfig.getInboundAuthKey(),
                                oAuthAppDO.getOauthConsumerKey()));
                    }
                    try {
                        if (!isUpdate) {
                            if (dao.isDuplicateConsumer(inboundAuthKey)) {
                                validationMsg.add(String.format("An OAuth application already exists with %s as " +
                                        "consumer key", inboundAuthKey));
                                break;
                            } else if (dao.isDuplicateApplication(userName,
                                    IdentityTenantUtil.getTenantId(tenantDomain), tenantDomain, oAuthAppDO)) {
                                validationMsg.add(String.format("An OAuth application already exists with %s as " +
                                        "consumer key", oAuthAppDO.getApplicationName()));
                                break;
                            }
                        }
                    } catch (IdentityOAuthAdminException e) {
                        // Do nothing, the key does exists.
                    }

                    if (oAuthAppDO.getGrantTypes() != null
                            && (oAuthAppDO.getGrantTypes().contains(OAuthConstants.GrantTypes.AUTHORIZATION_CODE)
                            || oAuthAppDO.getGrantTypes().contains(OAuthConstants.GrantTypes.IMPLICIT))
                            && StringUtils.isEmpty(oAuthAppDO.getCallbackUrl())) {
                        validationMsg.add("Callback Url is required for Code or Implicit grant types");
                    }

                    validateScopeValidators(oAuthAppDO.getScopeValidators(), validationMsg);

                    if (OAuthConstants.OAuthVersions.VERSION_2.equals(oAuthAppDO.getOauthVersion())) {
                        validateGrants(oAuthAppDO.getGrantTypes().split("\\s"), validationMsg);
                    }

                    break;
                }
            }
        }
        if (!validationMsg.isEmpty()) {
            throw new IdentityApplicationManagementValidationException(validationMsg.toArray(new String[0]));
        }
    }

    /**
     * Validate requested grants in the oauth app.
     *
     * @param requestedGrants list of requested grants
     * @param validationMsg      validation msg list
     */
    private void validateGrants(String[] requestedGrants, List<String> validationMsg) {

        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        List<String> allowedGrants = new ArrayList<>(Arrays.asList(oAuthAdminService.getAllowedGrantTypes()));
        for (String requestedGrant : requestedGrants) {
            if (StringUtils.isBlank(requestedGrant)) {
                continue;
            }
            if (!allowedGrants.contains(requestedGrant)) {
                validationMsg.add(String.format("Grant type %s not allowed", requestedGrant));
            }
        }
    }

    /**
     * Validate scope validators in the oauth app.
     *
     * @param appScopeValidators list of scope validators
     * @param validationMsg      validation msg list
     */
    private void validateScopeValidators(String[] appScopeValidators, List<String> validationMsg) {

        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        List<String> scopeValidators = new ArrayList<>(Arrays.asList(oAuthAdminService.getAllowedScopeValidators()));
        Arrays.stream(appScopeValidators).forEach(validator -> {
            if (!scopeValidators.contains(validator)) {
                validationMsg.add(String.format("The scope validator %s is not available in the " +
                        "server configuration. ", validator));
            }
        });
    }

    /**
     * Unmarshal oauth application to string.
     *
     * @param authApplication oauth application to be marshaled
     * @return string
     * @throws IdentityApplicationManagementException Identity Application Management Exception
     */
    private String unmarshelOAuthDO(OAuthAppDO authApplication) throws IdentityApplicationManagementException {

        try {
            JAXBContext jaxbContext = JAXBContext.newInstance(OAuthAppDO.class);
            Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
            jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            StringWriter sw = new StringWriter();
            jaxbMarshaller.marshal(authApplication, sw);
            return sw.toString();
        } catch (JAXBException e) {
            throw new IdentityApplicationManagementException(String.format("Error in exporting OAuth application " +
                    "%s@%s", authApplication.getApplicationName(), authApplication.getUser().getTenantDomain()), e);
        }
    }

    /**
     * Marshel oauth application.
     *
     * @param authConfig          xml of the oauth app
     * @param serviceProviderName service provider name
     * @param tenantDomain        tenant domain
     * @return OAuthAppDO
     * @throws IdentityApplicationManagementException Identity Application Management Exception
     */
    private OAuthAppDO marshelOAuthDO(String authConfig, String serviceProviderName, String tenantDomain) throws
            IdentityApplicationManagementException {

        try {
            JAXBContext jaxbContext = JAXBContext.newInstance(OAuthAppDO.class);
            Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
            return (OAuthAppDO) unmarshaller.unmarshal(new ByteArrayInputStream(
                    authConfig.getBytes(StandardCharsets.UTF_8)));
        } catch (JAXBException e) {
            throw new IdentityApplicationManagementException(String.format("Error in unmarshelling OAuth application " +
                    "%s@%s", serviceProviderName, tenantDomain), e);
        }
    }
}
