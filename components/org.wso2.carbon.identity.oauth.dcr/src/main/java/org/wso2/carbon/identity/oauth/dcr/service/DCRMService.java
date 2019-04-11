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
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthAdminService;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dcr.DCRMConstants;
import org.wso2.carbon.identity.oauth.dcr.bean.Application;
import org.wso2.carbon.identity.oauth.dcr.bean.ApplicationRegistrationRequest;
import org.wso2.carbon.identity.oauth.dcr.bean.ApplicationUpdateRequest;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMException;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMServerException;
import org.wso2.carbon.identity.oauth.dcr.internal.DCRDataHolder;
import org.wso2.carbon.identity.oauth.dcr.util.DCRConstants;
import org.wso2.carbon.identity.oauth.dcr.util.DCRMUtils;
import org.wso2.carbon.identity.oauth.dcr.util.ErrorCodes;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.user.core.UserCoreConstants;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;


/**
 * DCRMService service is used to manage OAuth2/OIDC application registration.
 */
public class DCRMService {
    private static final Log log = LogFactory.getLog(DCRMService.class);
    private static OAuthAdminService oAuthAdminService = new OAuthAdminService();

    private static final String AUTH_TYPE_OAUTH_2 = "oauth2";
    private static final String OAUTH_VERSION = "OAuth-2.0";
    private static final String GRANT_TYPE_SEPARATOR = " ";
    private static Pattern clientIdRegexPattern = null;

    /**
     * Get OAuth2/OIDC application information with client_id
     * @param clientId client_id of the application
     * @return
     * @throws DCRMException
     */
    public Application getApplication(String clientId) throws DCRMException {

        return buildResponse(getApplicationById(clientId));
    }

    /**
     * Get OAuth2/OIDC application information with client name
     *
     * @param clientName
     * @return Application
     * @throws DCRMException
     */
    public Application getApplicationByName(String clientName) throws DCRMException {

        if (StringUtils.isEmpty(clientName)) {
            throw DCRMUtils.generateClientException(
                    DCRMConstants.ErrorMessages.BAD_REQUEST_INSUFFICIENT_DATA, null);
        }

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        if (!isServiceProviderExist(clientName, tenantDomain)) {
            throw DCRMUtils.generateClientException(
                    DCRMConstants.ErrorMessages.NOT_FOUND_APPLICATION_WITH_NAME, clientName);
        }

        try {
            OAuthConsumerAppDTO oAuthConsumerAppDTO =
                    oAuthAdminService.getOAuthApplicationDataByAppName(clientName);
            if (!isUserAuthorized(oAuthConsumerAppDTO.getOauthConsumerKey())) {
                throw DCRMUtils.generateClientException(
                        DCRMConstants.ErrorMessages.FORBIDDEN_UNAUTHORIZED_USER, clientName);
            }
            return buildResponse(oAuthConsumerAppDTO);
        } catch (IdentityOAuthAdminException e) {
            throw DCRMUtils.generateServerException(
                    DCRMConstants.ErrorMessages.FAILED_TO_GET_APPLICATION, clientName, e);
        }

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
        String spName;
        try {
            spName = DCRDataHolder.getInstance().getApplicationManagementService()
                    .getServiceProviderNameByClientId(appDTO.getOauthConsumerKey(), DCRMConstants.OAUTH2, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new DCRMException("Error while retrieving the service provider.", e);
        }

        // If a SP name returned for the client ID then the application has an associated service provider.
        if (!StringUtils.equals(spName, IdentityApplicationConstants.DEFAULT_SP_CONFIG)) {
            if (log.isDebugEnabled()) {
                log.debug("The application with consumer key: " + appDTO.getOauthConsumerKey() +
                        " has an association with the service provider: " + spName);
            }
            deleteServiceProvider(spName, tenantDomain, applicationOwner);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("The application with consumer key: " + appDTO.getOauthConsumerKey() +
                        " doesn't have an associated service provider.");
            }
            deleteOAuthApplicationWithoutAssociatedSP(appDTO, tenantDomain, applicationOwner);
        }
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
        String clientName = updateRequest.getClientName();

        // Update Service Provider
        ServiceProvider sp = getServiceProvider(appDTO.getApplicationName(), tenantDomain);
        if (StringUtils.isNotEmpty(clientName)) {
            // Regex validation of the application name.
            if (!DCRMUtils.isRegexValidated(clientName)) {
                throw DCRMUtils.generateClientException(DCRMConstants.ErrorMessages.BAD_REQUEST_INVALID_SP_NAME,
                        DCRMUtils.getSPValidatorRegex(), null);
            }
            sp.setApplicationName(clientName);
            updateServiceProvider(sp, tenantDomain, applicationOwner);
        }

        // Update application
        try {
            if (StringUtils.isNotEmpty(clientName)) {
                // Regex validation of the application name.
                if (!DCRMUtils.isRegexValidated(clientName)) {
                    throw DCRMUtils.generateClientException(DCRMConstants.ErrorMessages.BAD_REQUEST_INVALID_SP_NAME,
                            DCRMUtils.getSPValidatorRegex(), null);
                }
                appDTO.setApplicationName(clientName);
            }
            if (!updateRequest.getGrantTypes().isEmpty()) {
                String grantType = StringUtils.join(updateRequest.getGrantTypes(), GRANT_TYPE_SEPARATOR);
                appDTO.setGrantTypes(grantType);
            }
            if (!updateRequest.getRedirectUris().isEmpty()) {
                String callbackUrl = validateAndSetCallbackURIs(updateRequest.getRedirectUris(), updateRequest.getGrantTypes());
                appDTO.setCallbackUrl(callbackUrl);
            }
            if (updateRequest.getTokenType() != null) {
                appDTO.setTokenType(updateRequest.getTokenType());
            }
            if(StringUtils.isNotEmpty(updateRequest.getBackchannelLogoutUri())) {
                String backChannelLogoutUri = validateBackchannelLogoutURI(updateRequest.getBackchannelLogoutUri());
                appDTO.setBackChannelLogoutUrl(backChannelLogoutUri);
            }
            oAuthAdminService.updateConsumerApplication(appDTO);
        } catch (IdentityOAuthAdminException e) {
            throw DCRMUtils.generateServerException(
                    DCRMConstants.ErrorMessages.FAILED_TO_UPDATE_APPLICATION, clientId, e);
        }

        return buildResponse(getApplicationById(clientId));
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
                throw DCRMUtils.generateClientException(
                        DCRMConstants.ErrorMessages.NOT_FOUND_APPLICATION_WITH_ID, clientId);
            } else if (!isUserAuthorized(clientId)) {
                throw DCRMUtils.generateClientException(
                        DCRMConstants.ErrorMessages.FORBIDDEN_UNAUTHORIZED_USER, clientId);
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
        String spName = registrationRequest.getClientName();
        String templateName = registrationRequest.getSpTemplateName();

        // Regex validation of the application name.
        if (!DCRMUtils.isRegexValidated(spName)) {
            throw DCRMUtils.generateClientException(DCRMConstants.ErrorMessages.BAD_REQUEST_INVALID_SP_NAME,
                    DCRMUtils.getSPValidatorRegex(), null);
        }

        // Check whether a service provider already exists for the name we are trying to register the OAuth app with.
        if (isServiceProviderExist(spName, tenantDomain)) {
            throw DCRMUtils.generateClientException(DCRMConstants.ErrorMessages.CONFLICT_EXISTING_APPLICATION, spName);
        }

        if (StringUtils.isNotEmpty(registrationRequest.getConsumerKey()) && isClientIdExist(
                registrationRequest.getConsumerKey())) {
            throw DCRMUtils.generateClientException(DCRMConstants.ErrorMessages.CONFLICT_EXISTING_CLIENT_ID,
                    registrationRequest.getConsumerKey());
        }

        // Create a service provider.
        ServiceProvider serviceProvider = createServiceProvider(applicationOwner, tenantDomain, spName, templateName);

        OAuthConsumerAppDTO createdApp;
        try {
            // Register the OAuth app.
            createdApp = createOAuthApp(registrationRequest, applicationOwner, tenantDomain, spName);
        } catch (DCRMException ex) {
            if (log.isDebugEnabled()) {
                log.debug("OAuth app: " + spName + " registration failed in tenantDomain: " + tenantDomain + ". " +
                        "Deleting the service provider: " + spName + " to rollback.");
            }
            deleteServiceProvider(spName, tenantDomain, applicationOwner);
            throw ex;
        }

        try {
            updateServiceProviderWithOAuthAppDetails(serviceProvider, createdApp, applicationOwner, tenantDomain);
        } catch (DCRMException ex) {
            // Delete the OAuth app created. This will also remove the registered SP for the OAuth app.
            deleteApplication(createdApp.getOauthConsumerKey());
            throw ex;
        }
        return buildResponse(createdApp);
    }

    private Application buildResponse(OAuthConsumerAppDTO createdApp) {
        Application application = new Application();
        application.setClient_name(createdApp.getApplicationName());
        application.setClient_id(createdApp.getOauthConsumerKey());
        application.setClient_secret(createdApp.getOauthConsumerSecret());

        List<String> redirectUrisList = new ArrayList<>();
        redirectUrisList.add(createdApp.getCallbackUrl());
        application.setRedirect_uris(redirectUrisList);

        return application;
    }

    private void updateServiceProviderWithOAuthAppDetails(ServiceProvider serviceProvider,
                                                          OAuthConsumerAppDTO createdApp,
                                                          String applicationOwner,
                                                          String tenantDomain) throws DCRMException {
        // Update created service provider, InboundAuthenticationConfig with OAuth application info.
        InboundAuthenticationConfig inboundAuthenticationConfig = new InboundAuthenticationConfig();
        List<InboundAuthenticationRequestConfig> inboundAuthenticationRequestConfigs = new ArrayList<>();

        InboundAuthenticationRequestConfig inboundAuthenticationRequestConfig =
                new InboundAuthenticationRequestConfig();
        inboundAuthenticationRequestConfig.setInboundAuthKey(createdApp.getOauthConsumerKey());
        inboundAuthenticationRequestConfig.setInboundAuthType(AUTH_TYPE_OAUTH_2);
        inboundAuthenticationRequestConfigs.add(inboundAuthenticationRequestConfig);
        inboundAuthenticationConfig.setInboundAuthenticationRequestConfigs(inboundAuthenticationRequestConfigs
                .toArray(new InboundAuthenticationRequestConfig[inboundAuthenticationRequestConfigs
                        .size()]));
        serviceProvider.setInboundAuthenticationConfig(inboundAuthenticationConfig);
        //Set SaaS app option
        serviceProvider.setSaasApp(false);

        // Update the Service Provider app to add OAuthApp as an Inbound Authentication Config
        updateServiceProvider(serviceProvider, tenantDomain, applicationOwner);
    }

    private OAuthConsumerAppDTO createOAuthApp(ApplicationRegistrationRequest registrationRequest,
                                               String applicationOwner,
                                               String tenantDomain,
                                               String spName) throws DCRMException {
        // Then Create OAuthApp
        OAuthConsumerAppDTO oAuthConsumerApp = new OAuthConsumerAppDTO();
        oAuthConsumerApp.setApplicationName(spName);
        oAuthConsumerApp.setCallbackUrl(
                validateAndSetCallbackURIs(registrationRequest.getRedirectUris(), registrationRequest.getGrantTypes()));
        String grantType = StringUtils.join(registrationRequest.getGrantTypes(), GRANT_TYPE_SEPARATOR);
        oAuthConsumerApp.setGrantTypes(grantType);
        oAuthConsumerApp.setOAuthVersion(OAUTH_VERSION);
        oAuthConsumerApp.setTokenType(registrationRequest.getTokenType());
        oAuthConsumerApp.setBackChannelLogoutUrl(
                validateBackchannelLogoutURI(registrationRequest.getBackchannelLogoutUri()));

        if (StringUtils.isNotEmpty(registrationRequest.getConsumerKey())) {
            String clientIdRegex = OAuthServerConfiguration.getInstance().getClientIdValidationRegex();
            if (clientIdMatchesRegex(registrationRequest.getConsumerKey(), clientIdRegex)) {
                oAuthConsumerApp.setOauthConsumerKey(registrationRequest.getConsumerKey());
            } else {
                throw DCRMUtils.generateClientException(DCRMConstants.ErrorMessages.BAD_REQUEST_CLIENT_ID_VIOLATES_PATTERN,
                        clientIdRegex);
            }
        }

        if (StringUtils.isNotEmpty(registrationRequest.getConsumerSecret())) {
            oAuthConsumerApp.setOauthConsumerSecret(registrationRequest.getConsumerSecret());
        }
        if (log.isDebugEnabled()) {
            log.debug("Creating OAuth Application: " + spName + " in tenant: " + tenantDomain);
        }
        try {
            oAuthAdminService.registerOAuthApplicationData(oAuthConsumerApp);
        } catch (IdentityOAuthAdminException e) {
            throw DCRMUtils.generateServerException(
                    DCRMConstants.ErrorMessages.FAILED_TO_REGISTER_APPLICATION, spName, e);
        }

        if (log.isDebugEnabled()) {
            log.debug("Created OAuth Application: " + spName + " in tenant: " + tenantDomain);
        }

        OAuthConsumerAppDTO createdApp;
        try {
            createdApp = oAuthAdminService.getOAuthApplicationDataByAppName(oAuthConsumerApp.getApplicationName());
        } catch (IdentityOAuthAdminException e) {
            throw DCRMUtils.generateServerException(
                    DCRMConstants.ErrorMessages.FAILED_TO_GET_APPLICATION, oAuthConsumerApp.getApplicationName(), e);
        }

        if (createdApp == null) {
            throw DCRMUtils.generateServerException(DCRMConstants.ErrorMessages.FAILED_TO_REGISTER_APPLICATION, spName);
        }

        if (log.isDebugEnabled()) {
            log.debug("Retrieved Details of OAuth App: " + createdApp.getApplicationName() + " in tenant: " +
                    tenantDomain);
        }
        return createdApp;
    }

    private ServiceProvider createServiceProvider(String applicationOwner, String tenantDomain,
                                                  String spName, String templateName) throws DCRMException {
        // Create the Service Provider
        ServiceProvider sp = new ServiceProvider();
        sp.setApplicationName(spName);
        User user = new User();
        user.setUserName(applicationOwner);
        user.setTenantDomain(tenantDomain);
        sp.setOwner(user);
        sp.setDescription("Service Provider for application " + spName);

        createServiceProvider(sp, tenantDomain, applicationOwner, templateName);

        // Get created service provider.
        ServiceProvider clientSP = getServiceProvider(spName, tenantDomain);
        if (clientSP == null) {
            throw DCRMUtils.generateClientException(DCRMConstants.ErrorMessages.FAILED_TO_REGISTER_SP, spName);
        }
        return clientSP;
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
            log.error("Error while retrieving service provider: " + serviceProviderName + " in tenant: " + tenantDomain);
        }

        return serviceProvider != null;
    }

    private boolean isClientIdExist(String clientId) {

        OAuthConsumerAppDTO app = null;
        try {
            app = getApplicationById(clientId);
        } catch (DCRMException e) {
            log.error("Error while retrieving oauth application with client id: " + clientId);
        }

        return app != null;
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
            DCRDataHolder.getInstance().getApplicationManagementService()
                    .updateApplication(serviceProvider, tenantDomain, userName);
        } catch (IdentityApplicationManagementException e) {
            throw DCRMUtils.generateServerException(
                    DCRMConstants.ErrorMessages.FAILED_TO_UPDATE_SP, serviceProvider.getApplicationName(), e);
        }
    }

    private void createServiceProvider(ServiceProvider serviceProvider, String tenantDomain, String username,
                                       String templateName) throws DCRMException {

        try {
            if (templateName != null) {
                boolean isTemplateExists = DCRDataHolder.getInstance().getApplicationManagementService()
                        .isExistingApplicationTemplate(templateName, tenantDomain);
                if (!isTemplateExists) {
                    throw DCRMUtils.generateClientException(DCRMConstants.ErrorMessages
                                    .BAD_REQUEST_INVALID_SP_TEMPLATE_NAME, templateName);
                }
            }
            DCRDataHolder.getInstance().getApplicationManagementService()
                    .createApplicationWithTemplate(serviceProvider, tenantDomain, username, templateName);
        } catch (IdentityApplicationManagementException e) {
            String errorMessage =
                    "Error while creating service provider: " + serviceProvider.getApplicationName() +
                            " in tenant: " + tenantDomain;
            throw new DCRMException(ErrorCodes.BAD_REQUEST.toString(), errorMessage, e);
        }
    }

    private void deleteServiceProvider(String applicationName,
                                       String tenantDomain, String userName) throws DCRMException {
        try {
            DCRDataHolder.getInstance().getApplicationManagementService()
                    .deleteApplication(applicationName, tenantDomain, userName);
        } catch (IdentityApplicationManagementException e) {
            throw DCRMUtils.generateServerException(DCRMConstants.ErrorMessages.FAILED_TO_DELETE_SP, applicationName, e);
        }
    }

    /**
     * Delete OAuth application when there is no associated service provider exists.
     *
     * @param appDTO       {@link OAuthConsumerAppDTO} object of the OAuth app to be deleted
     * @param tenantDomain Tenant Domain
     * @param username     User Name
     * @throws DCRMException
     */
    private void deleteOAuthApplicationWithoutAssociatedSP(OAuthConsumerAppDTO appDTO, String tenantDomain,
                                                           String username) throws DCRMException {

        try {
            if (log.isDebugEnabled()) {
                log.debug("Delete OAuth application with the consumer key: " + appDTO.getOauthConsumerKey());
            }
            oAuthAdminService.removeOAuthApplicationData(appDTO.getOauthConsumerKey());
        } catch (IdentityOAuthAdminException e) {
            throw new DCRMException("Error while deleting the OAuth application with consumer key: " +
                    appDTO.getOauthConsumerKey(), e);
        }

        ApplicationManagementService applicationManagementService = DCRDataHolder.getInstance()
                .getApplicationManagementService();
        try {
            if (log.isDebugEnabled()) {
                log.debug("Get service provider with application name: " + appDTO.getApplicationName());
            }
            ServiceProvider serviceProvider = applicationManagementService.getServiceProvider(appDTO
                    .getApplicationName(), tenantDomain);
            if (serviceProvider == null) {
                if (log.isDebugEnabled()) {
                    log.debug("There is no service provider exists with the name: " + appDTO.getApplicationName());
                }
            } else if (serviceProvider.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs()
                    .length == 0) {
                if (log.isDebugEnabled()) {
                    log.debug("Delete the service provider: " + serviceProvider.getApplicationName());
                }
                applicationManagementService.deleteApplication(serviceProvider.getApplicationName(), tenantDomain,
                        username);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Service provider with name: " + serviceProvider.getApplicationName() +
                            " can not be deleted since it has association with other application/s");
                }
            }
        } catch (IdentityApplicationManagementException e) {
            throw new DCRMException("Error while deleting the service provider with the name: " +
                    appDTO.getApplicationName(), e);
        }
    }

    private String validateAndSetCallbackURIs(List<String> redirectUris, List<String> grantTypes) throws DCRMException {

        //TODO: After implement multi-urls to the oAuth application, we have to change this API call
        //TODO: need to validate before processing request
        if (redirectUris.size() == 0) {
            if (isRedirectURIMandatory(grantTypes)) {
                String errorMessage = "RedirectUris property must have at least one URI value when using " +
                        "Authorization code or implicit grant types.";
                throw DCRMUtils.generateClientException(
                        DCRMConstants.ErrorMessages.BAD_REQUEST_INVALID_INPUT, errorMessage);
            } else {
                return StringUtils.EMPTY;
            }
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

    private String validateBackchannelLogoutURI(String backchannelLogoutUri) throws DCRMException {

        if (DCRMUtils.isBackchannelLogoutUriValid(backchannelLogoutUri)) {
            return backchannelLogoutUri;
        } else {
            throw DCRMUtils.generateClientException(
                    DCRMConstants.ErrorMessages.BAD_REQUEST_INVALID_BACKCHANNEL_LOGOUT_URI, backchannelLogoutUri);
        }
    }

    private boolean isRedirectURIMandatory(List<String> grantTypes) {
        return grantTypes.contains(DCRConstants.GrantTypes.AUTHORIZATION_CODE) ||
                grantTypes.contains(DCRConstants.GrantTypes.IMPLICIT);
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

    private boolean isUserAuthorized(String clientId) throws DCRMServerException {

        OAuthConsumerAppDTO oAuthConsumerAppDTO;
        try {
            // Get applications owned by the user
            oAuthConsumerAppDTO = oAuthAdminService.getOAuthApplicationData(clientId);
            String appUserName = oAuthConsumerAppDTO.getUsername();
            String threadLocalUserName = CarbonContext.getThreadLocalCarbonContext().getUsername().concat(UserCoreConstants.TENANT_DOMAIN_COMBINER).concat(CarbonContext.getThreadLocalCarbonContext().getTenantDomain());
            if (threadLocalUserName.equals(appUserName)) {
                return true;
            }
        } catch (IdentityOAuthAdminException e) {
            throw DCRMUtils.generateServerException(
                    DCRMConstants.ErrorMessages.FAILED_TO_GET_APPLICATION_BY_ID, clientId, e);
        }
        return false;
    }

    /**
     * Validate client id according to the regex
     *
     * @return validated or not
     */
    private static boolean clientIdMatchesRegex(String clientId, String clientIdValidatorRegex) {

        if (clientIdRegexPattern == null) {
            clientIdRegexPattern = Pattern.compile(clientIdValidatorRegex);
        }
        return clientIdRegexPattern.matcher(clientId).matches();
    }
}
