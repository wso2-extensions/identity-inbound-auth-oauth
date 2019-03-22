/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * you may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.dcr.service;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.context.RegistryType;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.base.IdentityValidationException;
import org.wso2.carbon.identity.base.IdentityValidationUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthAdminService;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dcr.DCRException;
import org.wso2.carbon.identity.oauth.dcr.internal.DCRDataHolder;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationRequestProfile;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationResponseProfile;
import org.wso2.carbon.identity.oauth.dcr.util.DCRConstants;
import org.wso2.carbon.identity.oauth.dcr.util.DCRMUtils;
import org.wso2.carbon.identity.oauth.dcr.util.ErrorCodes;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DCRManagementService {

    private static final Log log = LogFactory.getLog(DCRManagementService.class);

    private static final String AUTH_TYPE_OAUTH_2 = "oauth2";
    private static final String OAUTH_CONSUMER_SECRET = "oauthConsumerSecret";
    private static final String OAUTH_VERSION = "OAuth-2.0";
    // If client secret doesn't expire it should be 0
    private static final String DEFAULT_CLIENT_SECRET_EXPIRY_TIME = "0";

    private static DCRManagementService dcrManagementService = new DCRManagementService();

    private DCRManagementService() {
    }

    public static DCRManagementService getInstance() {
        return DCRManagementService.dcrManagementService;
    }

    /**
     * This method will register a new OAuth application using the data provided by
     * RegistrationRequestProfile.
     *
     * @param profile - RegistrationRequestProfile of the OAuth application to be created.
     * @return RegistrationResponseProfile object which holds the necessary data of created OAuth app.
     * @throws DCRException
     */
    public RegistrationResponseProfile registerOAuthApplication(RegistrationRequestProfile profile)
            throws DCRException {


        String applicationName = profile.getClientName();

        if (log.isDebugEnabled()) {
            log.debug("Trying to register OAuth application: '" + applicationName + "'");
        }
        // Regex validation of the application name.
        if (!DCRMUtils.isRegexValidated(applicationName)) {
            throw new DCRException("The Application name: " + applicationName + " is not valid! It is not adhering to" +
                    " the regex: " + DCRMUtils.getSPValidatorRegex());
        }

        RegistrationResponseProfile info = this.createOAuthApplication(profile);

        return info;
    }

    /**
     * @param profile - RegistrationRequestProfile of the OAuth application to be created.
     * @return RegistrationResponseProfile object which holds the necessary data of created OAuth app.
     * @throws DCRException
     * @throws IdentityException
     */
    private RegistrationResponseProfile createOAuthApplication(RegistrationRequestProfile profile)
            throws DCRException {

        //Subscriber's name should be passed as a parameter, since it's under the subscriber
        //the OAuth App is created.
        String owner =  profile.getOwner();
        // Replace all unsupported characters
        String ownerName = owner.replaceAll(String.valueOf(DCRConstants.UNSUPPORTED_CHARACTERS_IN_REGISTRY), "_");
        String applicationName = ownerName + "_" + profile.getClientName();
        // Regex validation of the application name.
        if (!DCRMUtils.isRegexValidated(applicationName)) {
            throw new DCRException("The Application name: " + applicationName + " is not valid! It is not adhering to" +
                    " the regex: " + DCRMUtils.getSPValidatorRegex());
        }

        String grantType = StringUtils.join(profile.getGrantTypes(), " ");
        String baseUser = CarbonContext.getThreadLocalCarbonContext().getUsername();
        String userName = MultitenantUtils.getTenantAwareUsername(profile.getOwner());

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(profile.getTenantDomain(), true);

        // Acting as the provided user. When creating Service Provider/OAuth App,
        // username is fetched from CarbonContext
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(userName);

        try {
            // Create the Service Provider
            ServiceProvider serviceProvider = new ServiceProvider();
            serviceProvider.setApplicationName(applicationName);
            User user = new User();
            user.setUserName(userName);
            user.setTenantDomain(profile.getTenantDomain());
            serviceProvider.setOwner(user);
            serviceProvider.setDescription("Service Provider for application " + applicationName);

            ApplicationManagementService appMgtService = DCRDataHolder.getInstance().
                    getApplicationManagementService();

            ServiceProvider existingServiceProvider = null;
            ServiceProvider createdServiceProvider = null;

            try {
                existingServiceProvider = appMgtService.getServiceProvider(applicationName, profile.getTenantDomain());
                if (existingServiceProvider == null) {
                    appMgtService.createApplication(serviceProvider, profile.getTenantDomain(), userName);
                    createdServiceProvider = appMgtService.getServiceProvider(applicationName,
                                                                              profile.getTenantDomain());
                } else {
                    String errorMessage = "Service Provider with name: " + applicationName +
                        " already registered";
                    throw IdentityException.error(DCRException.class,
                        ErrorCodes.META_DATA_VALIDATION_FAILED.toString(), errorMessage);
                }

            } catch (IdentityApplicationManagementException e) {
                String errorMessage = "Error occurred while reading service provider, " + applicationName;
                throw IdentityException.error(DCRException.class, ErrorCodes.BAD_REQUEST.toString(), errorMessage, e);
            }

            if (createdServiceProvider == null) {
                String errorMessage = "Couldn't create Service Provider Application " + applicationName;
                throw IdentityException.error(DCRException.class, ErrorCodes.META_DATA_VALIDATION_FAILED.toString(),
                        errorMessage);
            }
            //Set SaaS app option
            createdServiceProvider.setSaasApp(false);
            // Then Create OAuthApp
            OAuthAdminService oAuthAdminService = new OAuthAdminService();

            OAuthConsumerAppDTO oAuthConsumerApp = new OAuthConsumerAppDTO();
            oAuthConsumerApp.setApplicationName(applicationName);

            //TODO: After implement multi-urls to the oAuth application, we have to change this API call
            if (profile.getRedirectUris().size() == 0 && (profile.getGrantTypes().contains(
                    DCRConstants.GrantTypes.AUTHORIZATION_CODE) || profile.getGrantTypes().
                    contains(DCRConstants.GrantTypes.IMPLICIT))) {
                String errorMessage = "RedirectUris property must have at least one URI value.";
                throw IdentityException.error(DCRException.class, ErrorCodes.META_DATA_VALIDATION_FAILED.toString(),
                        errorMessage);
            } else if (profile.getRedirectUris().size() == 1) {
                String redirectUri = profile.getRedirectUris().get(0);
                try {
                    //validate the redirect uri
                    IdentityValidationUtil.getValidInputOverWhiteListPatterns(redirectUri,
                            new String[]{IdentityValidationUtil.ValidatorPattern.URL_WITHOUT_FRAGMENT.name()});
                    oAuthConsumerApp.setCallbackUrl(redirectUri);
                } catch (IdentityValidationException e) {
                    //TODO: need to add error code
                    throw IdentityException.error(DCRException.class,
                            "Redirect URI: " + redirectUri + ", is invalid", e);
                }

            } else if (profile.getRedirectUris().size() > 1) {
                oAuthConsumerApp.setCallbackUrl(OAuthConstants.CALLBACK_URL_REGEXP_PREFIX +
                        createRegexPattern(profile.getRedirectUris()));
            }
            oAuthConsumerApp.setGrantTypes(grantType);
            oAuthConsumerApp.setOAuthVersion(OAUTH_VERSION);
            if (log.isDebugEnabled()) {
                log.debug("Creating OAuth App " + applicationName);
            }

            OAuthConsumerAppDTO createdApp;
            try {
                createdApp = oAuthAdminService.registerAndRetrieveOAuthApplicationData(oAuthConsumerApp);
            } catch (IdentityOAuthAdminException e) {
                throw IdentityException.error(DCRException.class,
                        ErrorCodes.META_DATA_VALIDATION_FAILED.toString(), e.getMessage());
            }

            if (log.isDebugEnabled()) {
                log.debug("Created OAuth App " + applicationName);
                log.debug("Retrieved Details for OAuth App " + createdApp.getApplicationName());
            }

            // Set the OAuthApp in InboundAuthenticationConfig
            InboundAuthenticationConfig inboundAuthenticationConfig = new InboundAuthenticationConfig();
            List<InboundAuthenticationRequestConfig> inboundAuthenticationRequestConfigs = new ArrayList<>();

            InboundAuthenticationRequestConfig inboundAuthenticationRequestConfig =
                    new InboundAuthenticationRequestConfig();
            inboundAuthenticationRequestConfig.setInboundAuthKey(createdApp.getOauthConsumerKey());
            inboundAuthenticationRequestConfig.setInboundAuthType(AUTH_TYPE_OAUTH_2);
            String oauthConsumerSecret = createdApp.getOauthConsumerSecret();
            if (oauthConsumerSecret != null && !oauthConsumerSecret.isEmpty()) {
                Property property = new Property();
                property.setName(OAUTH_CONSUMER_SECRET);
                property.setValue(oauthConsumerSecret);
                Property[] properties = {property};
                inboundAuthenticationRequestConfig.setProperties(properties);
            }
            inboundAuthenticationRequestConfigs.add(inboundAuthenticationRequestConfig);
            inboundAuthenticationConfig.setInboundAuthenticationRequestConfigs(inboundAuthenticationRequestConfigs
                                                                                       .toArray(new InboundAuthenticationRequestConfig[inboundAuthenticationRequestConfigs
                                                                                               .size()]));
            createdServiceProvider.setInboundAuthenticationConfig(inboundAuthenticationConfig);

            // Update the Service Provider app to add OAuthApp as an Inbound Authentication Config
            try {
                appMgtService.updateApplication(createdServiceProvider, profile.getTenantDomain(), userName);
            } catch (IdentityApplicationManagementException e) {
                throw IdentityException.error(DCRException.class, ErrorCodes.BAD_REQUEST.toString(), e.getMessage());
            }

            RegistrationResponseProfile registrationResponseProfile = new RegistrationResponseProfile();
            registrationResponseProfile.setClientId(createdApp.getOauthConsumerKey());
            registrationResponseProfile.getRedirectUrls().add(createdApp.getCallbackUrl());
            registrationResponseProfile.setClientSecret(oauthConsumerSecret);
            registrationResponseProfile.setClientName(createdApp.getApplicationName());
            registrationResponseProfile.setClientSecretExpiresAt(DEFAULT_CLIENT_SECRET_EXPIRY_TIME);
            if (StringUtils.isNotBlank(createdApp.getGrantTypes())) {
                String[] split = createdApp.getGrantTypes().split(" ");
                registrationResponseProfile.setGrantTypes(Arrays.asList(split));
            }
            return registrationResponseProfile;

        } finally {
            PrivilegedCarbonContext.endTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(baseUser);
        }
    }

    /**
     * This method will unregister a created OAuth application.
     *
     * @param userId          - UserId of the owner
     * @param applicationName - OAuth application name
     * @param consumerKey     - ConsumerKey of the OAuth application
     * @return The status of the operation
     * @throws DCRException
     */
    public void unregisterOAuthApplication(String userId, String applicationName, String consumerKey)
            throws DCRException {

        if (!StringUtils.isNotEmpty(userId) || !StringUtils.isNotEmpty(applicationName) || !StringUtils
                .isNotEmpty(consumerKey)) {
            throw new DCRException(
                    "Username, Application Name and Consumer Key cannot be null or empty");
        }
        String tenantDomain = MultitenantUtils.getTenantDomain(userId);
        String userName = MultitenantUtils.getTenantAwareUsername(userId);

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain, true);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(userName);

        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        OAuthConsumerAppDTO oAuthConsumerApp = null;
        try {
            oAuthConsumerApp = oAuthAdminService.getOAuthApplicationData(consumerKey);
        } catch (Exception e) {
            //We had to catch Exception here because getOAuthApplicationData can throw exceptions of java.lang.Exception
            // class.
            if(log.isDebugEnabled()) {
                log.debug("Error occurred while oauth application data by consumer id.", e);
            }
        }

        if (oAuthConsumerApp != null) {
            try {
                oAuthAdminService.removeOAuthApplicationData(consumerKey);
                ApplicationManagementService appMgtService = DCRDataHolder.getInstance().
                        getApplicationManagementService();

                if (appMgtService == null) {
                    throw new IllegalStateException("Error occurred while retrieving Application Management Service");
                }
                ServiceProvider createdServiceProvider =
                        appMgtService.getServiceProvider(applicationName, tenantDomain);
                if (createdServiceProvider == null) {
                    throw new DCRException(
                            "Couldn't retrieve Service Provider Application " + applicationName);
                }
                appMgtService.deleteApplication(applicationName, tenantDomain, userName);

            } catch (IdentityApplicationManagementException e) {
                throw new DCRException(
                        "Error occurred while removing ServiceProvider for application '" + applicationName + "'", e);
            } catch (IdentityOAuthAdminException e) {
                throw new DCRException("Error occurred while removing application '" +
                                       applicationName + "'", e);
            } finally {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }
    }

    /**
     * This method will check the existence of an OAuth application provided application-name.
     *
     * @param applicationName - OAuth application name
     * @return The status of the operation
     * @throws DCRException
     */
    public boolean isOAuthApplicationAvailable(String applicationName) throws DCRException {
        ApplicationManagementService appMgtService = DCRDataHolder.getInstance().
                getApplicationManagementService();
        if (appMgtService == null) {
            throw new IllegalStateException("Error occurred while retrieving Application Management Service");
        }
        try {
            return appMgtService
                           .getServiceProvider(applicationName, CarbonContext.getThreadLocalCarbonContext()
                                   .getTenantDomain())
                   != null;
        } catch (IdentityApplicationManagementException e) {
            throw new DCRException(
                    "Error occurred while retrieving information of OAuthApp " + applicationName, e);
        }
    }

    private String createRegexPattern(List<String> redirectURIs) throws DCRException {
        StringBuilder regexPattern = new StringBuilder();
        for (String redirectURI : redirectURIs) {
            try {
                //validate the redirect uri
                IdentityValidationUtil.getValidInputOverWhiteListPatterns(redirectURI,
                        new String[]{IdentityValidationUtil.ValidatorPattern.URL_WITHOUT_FRAGMENT.name()});
                if (regexPattern.length() > 0) {
                    regexPattern.append("|").append(redirectURI);
                } else {
                    regexPattern.append("(").append(redirectURI);
                }
            } catch (IdentityValidationException e) {
                //TODO: need to add error code
                throw IdentityException.error(DCRException.class, "Redirect URI: " + redirectURI + ", is invalid", e);
            }
        }
        if (regexPattern.length() > 0) {
            regexPattern.append(")");
        }
        return regexPattern.toString();
    }

    protected Registry getConfigSystemRegistry() {
        return (Registry) PrivilegedCarbonContext.getThreadLocalCarbonContext().getRegistry(
                RegistryType.SYSTEM_CONFIGURATION);
    }

}
