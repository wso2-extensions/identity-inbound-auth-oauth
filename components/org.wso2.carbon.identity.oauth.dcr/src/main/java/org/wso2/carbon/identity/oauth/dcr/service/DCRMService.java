/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.dcr.service;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthAdminService;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dcr.DCRMConstants;
import org.wso2.carbon.identity.oauth.dcr.bean.Application;
import org.wso2.carbon.identity.oauth.dcr.bean.ApplicationRegistrationRequest;
import org.wso2.carbon.identity.oauth.dcr.bean.ApplicationUpdateRequest;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMException;
import org.wso2.carbon.identity.oauth.dcr.internal.DCRDataHolder;
import org.wso2.carbon.identity.oauth.dcr.util.DCRConstants;
import org.wso2.carbon.identity.oauth.dcr.util.DCRMUtils;
import org.wso2.carbon.identity.oauth.dcr.util.ErrorCodes;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;

import java.util.ArrayList;
import java.util.List;


/**
 * DCRMService service is used to manage OAuth2/OIDC application registration.
 */
public class DCRMService {
    private static final Log log = LogFactory.getLog(DCRMService.class);
    private static OAuthAdminService oAuthAdminService = new OAuthAdminService();

    private static final String AUTH_TYPE_OAUTH_2 = "oauth2";
    private static final String OAUTH_VERSION = "OAuth-2.0";

    /**
     * Get OAuth2/OIDC application information with client_id
     * @param clientId client_id of the application
     * @return
     * @throws DCRMException
     */
    public Application getApplication(String clientId) throws DCRMException {
        return getApplication(getApplicationById(clientId));
    }

    /**
     * Create OAuth2/OIDC application
     * @param registrationRequest
     * @return
     * @throws DCRMException
     */
    public Application registerApplication(ApplicationRegistrationRequest registrationRequest) throws DCRMException {
        return createOAuthApplication(registrationRequest);
    }

    /**
     * Delete OAuth2/OIDC application with client_id
     * @param clientId
     * @throws DCRMException
     */
    public void deleteApplication(String clientId) throws DCRMException {

        OAuthConsumerAppDTO appDTO = getApplicationById(clientId);
        String applicationOwner = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        deleteServiceProvider(appDTO.getApplicationName(), tenantDomain, applicationOwner);
    }

    /**
     * Update OAuth/OIDC application
     * @param updateRequest
     * @param clientId
     * @return
     * @throws DCRMException
     */
    public Application updateApplication(ApplicationUpdateRequest updateRequest, String clientId) throws DCRMException {

        OAuthConsumerAppDTO appDTO = getApplicationById(clientId);
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        String applicationOwner = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();

        // Update Service Provider
        ServiceProvider sp = getServiceProvider(appDTO.getApplicationName(), tenantDomain);
        if (StringUtils.isNotEmpty(updateRequest.getClientName())) {
            sp.setApplicationName(updateRequest.getClientName());
            updateServiceProvider(sp, tenantDomain, applicationOwner);
        }

        // Update application
        try {
            if (StringUtils.isNotEmpty(updateRequest.getClientName())) {
                appDTO.setApplicationName(updateRequest.getClientName());
            }
            if (!updateRequest.getGrantTypes().isEmpty()) {
                String grantType = StringUtils.join(updateRequest.getGrantTypes(), " ");
                appDTO.setGrantTypes(grantType);
            }
            if (!updateRequest.getRedirectUris().isEmpty()) {
                String callbackUrl = getCallbackUrl(updateRequest.getRedirectUris(), updateRequest.getGrantTypes());
                appDTO.setCallbackUrl(callbackUrl);
            }
            oAuthAdminService.updateConsumerApplication(appDTO);
        } catch (IdentityOAuthAdminException e) {
            throw DCRMUtils.generateServerException(
                    DCRMConstants.ErrorMessages.FAILED_TO_UPDATE_APPLICATION, clientId, e);
        }

        return getApplication(getApplicationById(clientId));

    }

    private OAuthConsumerAppDTO getApplicationById(String clientId) throws DCRMException {
        if (StringUtils.isEmpty(clientId)) {
            String errorMessage = "Invalid client_id";
            throw DCRMUtils.generateClientException(
                    DCRMConstants.ErrorMessages.BAD_REQUEST_INVALID_INPUT, errorMessage);
        }
        try {
            OAuthConsumerAppDTO dto = oAuthAdminService.getOAuthApplicationData(clientId);
            if (dto == null || StringUtils.isEmpty(dto.getApplicationName())) {
                throw DCRMUtils.generateClientException(DCRMConstants.ErrorMessages.NOT_FOUND_APPLICATION_WITH_ID, clientId);
            }
            return dto;
        } catch (IdentityOAuthAdminException e) {
            if (e.getCause() instanceof InvalidOAuthClientException) {
                throw DCRMUtils.generateClientException(DCRMConstants.ErrorMessages.NOT_FOUND_APPLICATION_WITH_ID, clientId);
            }
            throw DCRMUtils.generateServerException(
                    DCRMConstants.ErrorMessages.FAILED_TO_GET_APPLICATION_BY_ID, clientId, e);
        }
    }

    private Application createOAuthApplication(ApplicationRegistrationRequest registrationRequest)
            throws DCRMException {

        String applicationOwner = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        //Subscriber's name will append to the client application name to create unique application name.
        String spName = registrationRequest.getClientName();
        String grantType = StringUtils.join(registrationRequest.getGrantTypes(), " ");
        ServiceProvider clientSP;

        ApplicationManagementService appMgtService = DCRDataHolder.getInstance().
                getApplicationManagementService();
        if (appMgtService == null) {
            throw new IllegalStateException("Error occurred while retrieving Application Management Service");
        }

        // Check for existing service providers
        if (!isServiceProviderExist(spName, tenantDomain)) {
            // Create the Service Provider
            ServiceProvider sp = new ServiceProvider();
            sp.setApplicationName(spName);
            User user = new User();
            user.setUserName(applicationOwner);
            user.setTenantDomain(tenantDomain);
            sp.setOwner(user);
            sp.setDescription("Service Provider for application " + spName);

            createServiceProvider(sp, tenantDomain, applicationOwner);

            // Get created service provider, to update with OAuth/OIDC application information.
            clientSP = getServiceProvider(spName, tenantDomain);
        } else {
            throw DCRMUtils.generateClientException(
                    DCRMConstants.ErrorMessages.CONFLICT_EXISTING_APPLICATION, spName);
        }

        if (clientSP == null) {
            throw DCRMUtils.generateClientException(
                    DCRMConstants.ErrorMessages.FAILED_TO_REGISTER_SP, spName);
        }

        // Then Create OAuthApp
        OAuthConsumerAppDTO oAuthConsumerApp = new OAuthConsumerAppDTO();
        oAuthConsumerApp.setApplicationName(spName);
        oAuthConsumerApp.setCallbackUrl(getCallbackUrl(registrationRequest.getRedirectUris(), registrationRequest.getGrantTypes()));
        oAuthConsumerApp.setGrantTypes(grantType);
        oAuthConsumerApp.setOAuthVersion(OAUTH_VERSION);
        if (log.isDebugEnabled()) {
            log.debug("Creating OAuth Application: " + spName + " In tenant: " + tenantDomain);
        }

        try {
            oAuthAdminService.registerOAuthApplicationData(oAuthConsumerApp);
        } catch (IdentityOAuthAdminException e) {
            // Delete created service provider if error occured creating application
            if (log.isDebugEnabled()) {
                log.debug("Error ocured while creating OAuth application, " +
                        "hence delete the service provider: " + spName);
            }
            deleteServiceProvider(spName, tenantDomain, applicationOwner);

            throw DCRMUtils.generateServerException(
                    DCRMConstants.ErrorMessages.FAILED_TO_REGISTER_APPLICATION, spName, e);
        }

        if (log.isDebugEnabled()) {
            log.debug("Created OAuth Application: " + spName + " In tenant: " + tenantDomain);
        }

        OAuthConsumerAppDTO createdApp = null;

        try {
            createdApp = oAuthAdminService
                    .getOAuthApplicationDataByAppName(oAuthConsumerApp.getApplicationName());
        } catch (IdentityOAuthAdminException e) {
            throw DCRMUtils.generateServerException(
                    DCRMConstants.ErrorMessages.FAILED_TO_GET_APPLICATION, oAuthConsumerApp.getApplicationName()
                    , e);
        }

        if (log.isDebugEnabled()) {
            log.debug("Retrieved Details for OAuth Application: " + createdApp.getApplicationName() + " In tenant: " + tenantDomain);
        }

        // Update created service provider, InboundAuthenticationConfig with OAuth application info.
        InboundAuthenticationConfig inboundAuthenticationConfig = new InboundAuthenticationConfig();
        List<InboundAuthenticationRequestConfig> inboundAuthenticationRequestConfigs = new ArrayList<>();

        InboundAuthenticationRequestConfig inboundAuthenticationRequestConfig =
                new InboundAuthenticationRequestConfig();
        inboundAuthenticationRequestConfig.setInboundAuthKey(createdApp.getOauthConsumerKey());
        inboundAuthenticationRequestConfig.setInboundAuthType(AUTH_TYPE_OAUTH_2);
//        String oauthConsumerSecret = createdApp.getOauthConsumerSecret();
//        if (oauthConsumerSecret != null && !oauthConsumerSecret.isEmpty()) {
//            Property property = new Property();
//            property.setName(OAUTH_CONSUMER_SECRET);
//            property.setValue(oauthConsumerSecret);
//            Property[] properties = {property};
//            inboundAuthenticationRequestConfig.setProperties(properties);
//        }
        inboundAuthenticationRequestConfigs.add(inboundAuthenticationRequestConfig);
        inboundAuthenticationConfig.setInboundAuthenticationRequestConfigs(inboundAuthenticationRequestConfigs
                .toArray(new InboundAuthenticationRequestConfig[inboundAuthenticationRequestConfigs
                        .size()]));
        clientSP.setInboundAuthenticationConfig(inboundAuthenticationConfig);
        //Set SaaS app option
        clientSP.setSaasApp(false);

        // Update the Service Provider app to add OAuthApp as an Inbound Authentication Config
        updateServiceProvider(clientSP, tenantDomain, applicationOwner);
        return getApplication(createdApp);
    }

    /**
     * Check whether servers provider exist with a given name in the tenant.
     *
     * @param serviceProviderName
     * @param tenantDomain
     * @return
     */
    private boolean isServiceProviderExist(String serviceProviderName, String tenantDomain) {

        ServiceProvider serviceProvider = null;
        try {
            serviceProvider = getServiceProvider(serviceProviderName, tenantDomain);
        } catch (DCRMException e) {
            log.error("Error while retriving service provider: " + serviceProviderName + " in tenant: " + tenantDomain);
        }

        return serviceProvider == null ? false : true;
    }

    private ServiceProvider getServiceProvider(String applicationName, String tenantDomain) throws DCRMException {
        ServiceProvider serviceProvider = null;
        try {
            serviceProvider = DCRDataHolder.getInstance().getApplicationManagementService().getServiceProvider(applicationName, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw DCRMUtils.generateServerException(
                    DCRMConstants.ErrorMessages.FAILED_TO_GET_SP, applicationName, e);
        }
        return serviceProvider;
    }

    private void updateServiceProvider(ServiceProvider serviceProvider, String tenantDomain, String userName) throws DCRMException {
        try {
            DCRDataHolder.getInstance().getApplicationManagementService().updateApplication(serviceProvider, tenantDomain, userName);
        } catch (IdentityApplicationManagementException e) {
            throw DCRMUtils.generateServerException(
                    DCRMConstants.ErrorMessages.FAILED_TO_UPDATE_SP, serviceProvider.getApplicationName(), e);
        }
    }

    private void createServiceProvider(ServiceProvider serviceProvider, String applicationName, String tenantDomain) throws DCRMException {
        try {
            DCRDataHolder.getInstance().getApplicationManagementService().createApplication(serviceProvider, applicationName, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            String errorMessage = "Error while creating service provider: " + applicationName + " in tenant: " + tenantDomain;
            throw new DCRMException(ErrorCodes.BAD_REQUEST.toString(), errorMessage, e);
        }
    }

    private void deleteServiceProvider(String applicationName, String tenantDomain, String userName) throws DCRMException {
        try {
            DCRDataHolder.getInstance().getApplicationManagementService().deleteApplication(applicationName, tenantDomain, userName);
        } catch (IdentityApplicationManagementException e) {
            throw DCRMUtils.generateServerException(
                    DCRMConstants.ErrorMessages.FAILED_TO_DELETE_SP, applicationName, e);

        }
    }

    private Application getApplication(OAuthConsumerAppDTO appDTO) {

        Application application = new Application();
        application.setClient_name(appDTO.getApplicationName());
        application.setClient_id(appDTO.getOauthConsumerKey());
        application.setClient_secret(appDTO.getOauthConsumerSecret());
        List<String> redirectUrisList = new ArrayList<>();
        redirectUrisList.add(appDTO.getCallbackUrl());
        application.setRedirect_uris(redirectUrisList);

        return application;

    }

    private String getCallbackUrl(List<String> redirectUris, List<String> grantTypes) throws DCRMException {

        //TODO: After implement multi-urls to the oAuth application, we have to change this API call
        //TODO: need to validate before processing request
        if (redirectUris.size() == 0 && (grantTypes.contains(
                DCRConstants.GrantTypes.AUTHORIZATION_CODE) || grantTypes.
                contains(DCRConstants.GrantTypes.IMPLICIT))) {
            String errorMessage = "RedirectUris property must have at least one URI value.";
            throw DCRMUtils.generateClientException(
                    DCRMConstants.ErrorMessages.BAD_REQUEST_INVALID_INPUT, errorMessage);
        } else if (redirectUris.size() == 1) {
            String redirectUri = redirectUris.get(0);
            if (DCRMUtils.isRedirectionUriValid(redirectUri)) {
                return redirectUri;
            } else {
                throw DCRMUtils.generateClientException(
                        DCRMConstants.ErrorMessages.BAD_REQUEST_INVALID_REDIRECT_URI, redirectUri);
            }

        } else {
            return OAuthConstants.CALLBACK_URL_REGEXP_PREFIX + createRegexPattern(redirectUris);
        }
    }

    private String createRegexPattern(List<String> redirectURIs) throws DCRMException {
        StringBuilder regexPattern = new StringBuilder();
        for (String redirectURI : redirectURIs) {
            if (DCRMUtils.isRedirectionUriValid(redirectURI)) {
                if (regexPattern.length() > 0) {
                    regexPattern.append("|").append(redirectURI);
                } else {
                    regexPattern.append("(").append(redirectURI);
                }
            } else {
                throw DCRMUtils.generateClientException(
                        DCRMConstants.ErrorMessages.BAD_REQUEST_INVALID_REDIRECT_URI, redirectURI);
            }
        }
        if (regexPattern.length() > 0) {
            regexPattern.append(")");
        }
        return regexPattern.toString();
    }
}
