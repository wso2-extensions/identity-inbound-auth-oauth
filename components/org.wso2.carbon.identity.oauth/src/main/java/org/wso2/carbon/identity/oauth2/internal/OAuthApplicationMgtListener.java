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
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
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
import org.wso2.carbon.identity.oauth.OAuthAdminService;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.dao.OAuthConsumerDAO;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;

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

        storeSaaSPropertyValue(serviceProvider);
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
        removeEntriesFromCache(serviceProvider, tenantDomain, userName);
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
        if (serviceProvider != null) {
            removeEntriesFromCache(serviceProvider, tenantDomain, userName);
            if (OAuth2ServiceComponentHolder.isAudienceEnabled()) {
                removeOauthConsumerAppProperties(serviceProvider, tenantDomain);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Service Provider not found with name: " + applicationName);
            }
        }
        return true;
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
                        oAuthAppDO.setUser(buildAuthenticatedUser(owner));

                        OAuthConsumerAppDTO oAuthConsumerAppDTO = OAuthUtil.buildConsumerAppDTO(oAuthAppDO);
                        if (oAuthConsumerAppDTO.getOauthConsumerSecret() == null) {
                            oAuthConsumerAppDTO.setOauthConsumerSecret(OAuthUtil.getRandomNumber());
                        }
                        OAuthAdminService oAuthAdminService = new OAuthAdminService();
                        OAuthAppDAO dao = new OAuthAppDAO();
                        if (dao.isDuplicateConsumer(oAuthConsumerAppDTO.getOauthConsumerKey())) {
                            oAuthAdminService.updateConsumerApplication(oAuthConsumerAppDTO);
                        } else {
                            oAuthAdminService.registerOAuthApplicationData(oAuthConsumerAppDTO);
                        }
                        return;
                    }
                }
            }
        } catch (IdentityOAuthAdminException e) {
            throw new IdentityApplicationManagementException("Error occurred when importing OAuth application ", e);
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
                        OAuthAppDO authApplication = dao.getAppInformationByAppName(serviceProvider
                                .getApplicationName());
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
                    accessTokens.addAll(OAuthTokenPersistenceFactory.getInstance()
                            .getAccessTokenDAO().getActiveTokensByConsumerKey(oauthKey));
                    authorizationCodes.addAll(OAuthTokenPersistenceFactory.getInstance()
                            .getAuthorizationCodeDAO().getAuthorizationCodesByConsumerKey(oauthKey));
                    // Remove client credential from AppInfoCache
                    appInfoCache.clearCacheEntry(oauthKey);
                    OAuthCache.getInstance().clearCacheEntry(new OAuthCacheKey(oauthKey));
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
     * @throws IdentityApplicationManagementException
     */
    private void storeSaaSPropertyValue(ServiceProvider serviceProvider) throws IdentityApplicationManagementException {

        ServiceProvider sp = OAuth2ServiceComponentHolder.getApplicationMgtService()
                .getServiceProvider(serviceProvider.getApplicationID());
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

                new Thread(new Runnable() {
                    public void run() {
                        InboundAuthenticationRequestConfig[] configs = serviceProvider.getInboundAuthenticationConfig()
                                .getInboundAuthenticationRequestConfigs();
                        for (InboundAuthenticationRequestConfig config : configs) {
                            if (IdentityApplicationConstants.OAuth2.NAME.equalsIgnoreCase(config.getInboundAuthType()) &&
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
                    }
                }).start();
            }
        } finally {
            IdentityUtil.threadLocalProperties.get().remove(SAAS_PROPERTY);
        }
    }

    /**
     * Remove oauth consumer app related properties.
     *
     * @param serviceProvider Service provider
     * @param tenantDomain Application tenant domain
     * @throws IdentityApplicationManagementException
     */
    private void removeOauthConsumerAppProperties(ServiceProvider serviceProvider, String tenantDomain) throws IdentityApplicationManagementException {

        try {
            InboundAuthenticationConfig inboundAuthenticationConfig = serviceProvider.getInboundAuthenticationConfig();
            if (inboundAuthenticationConfig != null) {
                InboundAuthenticationRequestConfig[] inboundRequestConfigs = inboundAuthenticationConfig.
                        getInboundAuthenticationRequestConfigs();
                if (inboundRequestConfigs != null) {
                    for (InboundAuthenticationRequestConfig inboundRequestConfig : inboundRequestConfigs) {
                        if (StringUtils.equals(OAUTH2, inboundRequestConfig.getInboundAuthType()) || StringUtils
                                .equals(inboundRequestConfig.getInboundAuthType(), OAUTH)) {
                            String oauthKey = inboundRequestConfig.getInboundAuthKey();
                            OAuthAppDAO oAuthAppDAO = new OAuthAppDAO();
                            oAuthAppDAO.removeOIDCProperties(tenantDomain, oauthKey);
                        }
                    }
                }
            }
        } catch (IdentityOAuthAdminException ex) {
            throw new IdentityApplicationManagementException("Error occurred while removing OIDC properties " +
                    "for application:" + serviceProvider.getApplicationName() + " in tenant domain: " + tenantDomain);
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

                    if ((oAuthAppDO.getGrantTypes().contains(OAuthConstants.GrantTypes.AUTHORIZATION_CODE)
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
     * Creates authenticated user obj from user obj.
     *
     * @param user user
     * @return authenticated user
     */
    private AuthenticatedUser buildAuthenticatedUser(User user) {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(user.getUserName());
        authenticatedUser.setTenantDomain(user.getTenantDomain());
        authenticatedUser.setUserStoreDomain(user.getUserStoreDomain());
        return authenticatedUser;
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
