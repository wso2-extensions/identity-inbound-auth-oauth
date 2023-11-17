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

import com.google.gson.Gson;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.mgt.ApplicationMgtUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.IdentityOAuthClientException;
import org.wso2.carbon.identity.oauth.OAuthAdminService;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dcr.DCRMConstants;
import org.wso2.carbon.identity.oauth.dcr.bean.Application;
import org.wso2.carbon.identity.oauth.dcr.bean.ApplicationRegistrationRequest;
import org.wso2.carbon.identity.oauth.dcr.bean.ApplicationUpdateRequest;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMClientException;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMException;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMServerException;
import org.wso2.carbon.identity.oauth.dcr.internal.DCRDataHolder;
import org.wso2.carbon.identity.oauth.dcr.util.DCRConstants;
import org.wso2.carbon.identity.oauth.dcr.util.DCRMUtils;
import org.wso2.carbon.identity.oauth.dcr.util.ErrorCodes;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.util.JWTSignatureValidationUtils;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.wso2.carbon.identity.oauth.Error.INVALID_OAUTH_CLIENT;

/**
 * DCRMService service is used to manage OAuth2/OIDC application registration.
 */
public class DCRMService {

    private static final Log log = LogFactory.getLog(DCRMService.class);
    private static OAuthAdminService oAuthAdminService = new OAuthAdminService();
    private static final String AUTH_TYPE_OAUTH_2 = "oauth2";
    private static final String OAUTH_VERSION = "OAuth-2.0";
    private static final String GRANT_TYPE_SEPARATOR = " ";
    private static final String APP_DISPLAY_NAME = "DisplayName";
    private static Pattern clientIdRegexPattern = null;
    private static final String SSA_VALIDATION_JWKS = "OAuth.DCRM.SoftwareStatementJWKS";


    /**
     * Get OAuth2/OIDC application information with client_id.
     *
     * @param clientId client_id of the application
     * @return
     * @throws DCRMException
     */
    public Application getApplication(String clientId) throws DCRMException {

        validateRequestTenantDomain(clientId);
        OAuthConsumerAppDTO consumerAppDTO = getApplicationById(
                clientId, DCRMUtils.isApplicationRolePermissionRequired());
        // Get the jwksURI from the service provider.
        String applicationName = consumerAppDTO.getApplicationName();
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        ServiceProvider serviceProvider = getServiceProvider(applicationName, tenantDomain);
        String jwksURI = serviceProvider.getJwksUri();
        if (StringUtils.isNotEmpty(jwksURI)) {
            consumerAppDTO.setJwksURI(jwksURI);
        }
        return buildResponse(consumerAppDTO);
    }

    /**
     * Get OAuth2/OIDC application information with client name.
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
            if (INVALID_OAUTH_CLIENT.getErrorCode().equals(e.getErrorCode())) {
                throw DCRMUtils.generateClientException(
                        DCRMConstants.ErrorMessages.NOT_FOUND_OAUTH_APPLICATION_WITH_NAME, clientName);
            }
            throw DCRMUtils.generateServerException(
                    DCRMConstants.ErrorMessages.FAILED_TO_GET_APPLICATION, clientName, e);
        }
    }

    /**
     * Create OAuth2/OIDC application.
     *
     * @param registrationRequest
     * @return
     * @throws DCRMException
     */
    public Application registerApplication(ApplicationRegistrationRequest registrationRequest) throws DCRMException {

        return createOAuthApplication(registrationRequest);
    }

    /**
     * Delete OAuth2/OIDC application with client_id.
     *
     * @param clientId
     * @throws DCRMException
     */
    public void deleteApplication(String clientId) throws DCRMException {

        validateRequestTenantDomain(clientId);
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
     * Update OAuth/OIDC application.
     *
     * @param updateRequest
     * @param clientId
     * @return
     * @throws DCRMException
     */
    public Application updateApplication(ApplicationUpdateRequest updateRequest, String clientId) throws DCRMException {

        validateRequestTenantDomain(clientId);
        OAuthConsumerAppDTO appDTO = getApplicationById(clientId);
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        String applicationOwner = StringUtils.isNotBlank(updateRequest.getExtApplicationOwner()) ?
                updateRequest.getExtApplicationOwner() :
                PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
        String clientName = updateRequest.getClientName();

        // Update Service Provider
        ServiceProvider sp = getServiceProvider(appDTO.getApplicationName(), tenantDomain);
        if (StringUtils.isNotEmpty(clientName)) {
            // Check whether a service provider already exists for the name we are trying
            // to register the OAuth app with.
            if (!appDTO.getApplicationName().equals(clientName) && isServiceProviderExist(clientName, tenantDomain)) {
                throw DCRMUtils.generateClientException(DCRMConstants.ErrorMessages.CONFLICT_EXISTING_APPLICATION,
                        clientName);
            }

            // Regex validation of the application name.
            if (!DCRMUtils.isRegexValidated(clientName)) {
                throw DCRMUtils.generateClientException(DCRMConstants.ErrorMessages.BAD_REQUEST_INVALID_SP_NAME,
                        DCRMUtils.getSPValidatorRegex(), null);
            }
            if (sp == null) {
                throw DCRMUtils.generateClientException(DCRMConstants.ErrorMessages.FAILED_TO_GET_SP,
                        appDTO.getApplicationName(), null);
            }
            // Validate software statement assertion signature.
            if (StringUtils.isNotEmpty(updateRequest.getSoftwareStatement())) {
                try {
                    validateSSASignature(updateRequest.getSoftwareStatement());
                } catch (IdentityOAuth2Exception e) {
                    throw new DCRMClientException(DCRMConstants.ErrorCodes.INVALID_SOFTWARE_STATEMENT,
                            DCRMConstants.ErrorMessages.SIGNATURE_VALIDATION_FAILED.getMessage(), e);
                }
            }
            // Update the service provider properties list with the display name property.
            updateServiceProviderPropertyList(sp, updateRequest.getExtApplicationDisplayName());
            // Update jwksURI.
            if (StringUtils.isNotEmpty(updateRequest.getJwksURI())) {
                sp.setJwksUri(updateRequest.getJwksURI());
            }
            // Need to create a deep clone, since modifying the fields of the original object,
            // will modify the cached SP object.
            ServiceProvider clonedSP = cloneServiceProvider(sp);
            clonedSP.setApplicationName(clientName);
            updateServiceProvider(clonedSP, tenantDomain, applicationOwner);
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
                String callbackUrl =
                        validateAndSetCallbackURIs(updateRequest.getRedirectUris(), updateRequest.getGrantTypes());
                appDTO.setCallbackUrl(callbackUrl);
            }
            if (updateRequest.getTokenType() != null) {
                appDTO.setTokenType(updateRequest.getTokenType());
            }
            if (StringUtils.isNotEmpty(updateRequest.getBackchannelLogoutUri())) {
                String backChannelLogoutUri = validateBackchannelLogoutURI(updateRequest.getBackchannelLogoutUri());
                appDTO.setBackChannelLogoutUrl(backChannelLogoutUri);
            }
            if (updateRequest.getExtApplicationTokenLifetime() != null) {
                appDTO.setApplicationAccessTokenExpiryTime(updateRequest.getExtApplicationTokenLifetime());
            }
            if (updateRequest.getExtUserTokenLifetime() != null) {
                appDTO.setUserAccessTokenExpiryTime(updateRequest.getExtUserTokenLifetime());
            }
            if (updateRequest.getExtRefreshTokenLifetime() != null) {
                appDTO.setRefreshTokenExpiryTime(updateRequest.getExtRefreshTokenLifetime());
            }
            if (updateRequest.getExtIdTokenLifetime() != null) {
                appDTO.setIdTokenExpiryTime(updateRequest.getExtIdTokenLifetime());
            }
            if (updateRequest.getTokenEndpointAuthMethod() != null) {
                appDTO.setTokenEndpointAuthMethod(updateRequest.getTokenEndpointAuthMethod());
            }
            if (updateRequest.getTokenEndpointAuthSignatureAlgorithm() != null) {
                appDTO.setTokenEndpointAuthSignatureAlgorithm
                        (updateRequest.getTokenEndpointAuthSignatureAlgorithm());
            }
            if (updateRequest.getSectorIdentifierURI() != null) {
                appDTO.setSectorIdentifierURI(updateRequest.getSectorIdentifierURI());
            }
            if (updateRequest.getIdTokenSignatureAlgorithm() != null) {
                appDTO.setIdTokenSignatureAlgorithm(updateRequest.getIdTokenSignatureAlgorithm());
            }
            if (updateRequest.getIdTokenEncryptionAlgorithm() != null) {
                appDTO.setIdTokenEncryptionAlgorithm(updateRequest.getIdTokenEncryptionAlgorithm());
            }
            if (updateRequest.getIdTokenEncryptionMethod() != null) {
                appDTO.setIdTokenEncryptionMethod(updateRequest.getIdTokenEncryptionMethod());
            }
            if (updateRequest.getRequestObjectSignatureAlgorithm() != null) {
                appDTO.setRequestObjectSignatureAlgorithm(updateRequest.getRequestObjectSignatureAlgorithm());
            }
            if (updateRequest.getTlsClientAuthSubjectDN() != null) {
                appDTO.setTlsClientAuthSubjectDN(updateRequest.getTlsClientAuthSubjectDN());
            }
            if (updateRequest.getSubjectType() != null) {
                appDTO.setSubjectType(updateRequest.getSubjectType());
            }
            if (updateRequest.getRequestObjectEncryptionAlgorithm() != null) {
                appDTO.setRequestObjectEncryptionAlgorithm
                        (updateRequest.getRequestObjectEncryptionAlgorithm());
            }
            if (updateRequest.getRequestObjectEncryptionMethod() != null) {
                appDTO.setRequestObjectEncryptionMethod(updateRequest.getRequestObjectEncryptionMethod());
            }
            appDTO.setRequestObjectSignatureValidationEnabled(updateRequest.isRequireSignedRequestObject());
            appDTO.setRequirePushedAuthorizationRequests(updateRequest.isRequirePushedAuthorizationRequests());
            if (updateRequest.isTlsClientCertificateBoundAccessTokens()) {
                boolean isCertificateTokenBinderAvailable = DCRDataHolder.getInstance().getTokenBinders().stream()
                        .anyMatch(t -> OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER
                                .equals(t.getBindingType()));
                if (isCertificateTokenBinderAvailable) {
                    appDTO.setTokenBindingType(OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER);
                    appDTO.setTokenBindingValidationEnabled(true);
                }
            } else {
                appDTO.setTokenBindingType(OAuthConstants.TokenBindings.NONE);
            }
            appDTO.setPkceMandatory(updateRequest.isExtPkceMandatory());
            appDTO.setPkceSupportPlain(updateRequest.isExtPkceSupportPlain());
            appDTO.setBypassClientCredentials(updateRequest.isExtPublicClient());
            oAuthAdminService.updateConsumerApplication(appDTO);
        } catch (IdentityOAuthClientException e) {
            throw new DCRMClientException(DCRMConstants.ErrorCodes.INVALID_CLIENT_METADATA, e.getMessage(), e);
        } catch (IdentityOAuthAdminException e) {
            throw DCRMUtils.generateServerException(
                    DCRMConstants.ErrorMessages.FAILED_TO_UPDATE_APPLICATION, clientId, e);
        }
        OAuthConsumerAppDTO oAuthConsumerAppDTO = getApplicationById(clientId);
        // Setting the jwksURI to be sent in the response.
        oAuthConsumerAppDTO.setJwksURI(updateRequest.getJwksURI());
        Application application = buildResponse(oAuthConsumerAppDTO);
        application.setSoftwareStatement(updateRequest.getSoftwareStatement());
        return application;
    }

    /**
     * Update the service provider properties with the application display name.
     *
     * @param serviceProvider        Service provider.
     * @param applicationDisplayName Application display name.
     */
    private void updateServiceProviderPropertyList(ServiceProvider serviceProvider, String applicationDisplayName) {

        // Retrieve existing service provider properties.
        ServiceProviderProperty[] serviceProviderProperties = serviceProvider.getSpProperties();

        boolean isDisplayNameSet = Arrays.stream(serviceProviderProperties)
                .anyMatch(property -> property.getName().equals(APP_DISPLAY_NAME));
        if (!isDisplayNameSet) {
            /* Append application display name related property. This property is used when displaying the app name
            within the consent page.
             */
            ServiceProviderProperty serviceProviderProperty = new ServiceProviderProperty();
            serviceProviderProperty.setName(APP_DISPLAY_NAME);
            serviceProviderProperty.setValue(applicationDisplayName);
            serviceProviderProperties = (ServiceProviderProperty[]) ArrayUtils.add(serviceProviderProperties,
                    serviceProviderProperty);

            // Update service provider property list.
            serviceProvider.setSpProperties(serviceProviderProperties);
        }
    }

    private OAuthConsumerAppDTO getApplicationById(String clientId) throws DCRMException {

        return getApplicationById(clientId, true);
    }

    private OAuthConsumerAppDTO getApplicationById(String clientId, boolean isApplicationRolePermissionRequired)
            throws DCRMException {

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
            } else if (isApplicationRolePermissionRequired && !isUserAuthorized(clientId)) {
                throw DCRMUtils.generateClientException(
                        DCRMConstants.ErrorMessages.FORBIDDEN_UNAUTHORIZED_USER, clientId);
            }
            return dto;
        } catch (IdentityOAuthAdminException e) {
            if (e.getCause() instanceof InvalidOAuthClientException) {
                throw DCRMUtils
                        .generateClientException(DCRMConstants.ErrorMessages.NOT_FOUND_APPLICATION_WITH_ID, clientId);
            }
            throw DCRMUtils.generateServerException(
                    DCRMConstants.ErrorMessages.FAILED_TO_GET_APPLICATION_BY_ID, clientId, e);
        }
    }

    private Application createOAuthApplication(ApplicationRegistrationRequest registrationRequest)
            throws DCRMException {

        String applicationOwner = StringUtils.isNotBlank(registrationRequest.getExtApplicationOwner()) ?
                registrationRequest.getExtApplicationOwner() :
                PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        String spName = registrationRequest.getClientName();
        String templateName = registrationRequest.getSpTemplateName();
        boolean isManagementApp = registrationRequest.isManagementApp();

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
        // Validate software statement assertion signature.
        if (StringUtils.isNotEmpty(registrationRequest.getSoftwareStatement())) {
            try {
                validateSSASignature(registrationRequest.getSoftwareStatement());
            } catch (IdentityOAuth2Exception e) {
                throw new DCRMClientException(DCRMConstants.ErrorCodes.INVALID_SOFTWARE_STATEMENT,
                        DCRMConstants.ErrorMessages.SIGNATURE_VALIDATION_FAILED.getMessage(), e);
            }
        }

        // Create a service provider.
        ServiceProvider serviceProvider = createServiceProvider(applicationOwner, tenantDomain, spName, templateName,
                isManagementApp);

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

        // Update the service provider properties list with the display name property.
        updateServiceProviderPropertyList(serviceProvider, registrationRequest.getExtApplicationDisplayName());
        // Store jwksURI.
        if (StringUtils.isNotEmpty(registrationRequest.getJwksURI())) {
            serviceProvider.setJwksUri(registrationRequest.getJwksURI());
        }

        try {
            updateServiceProviderWithOAuthAppDetails(serviceProvider, createdApp, applicationOwner, tenantDomain);
            // Setting the jwksURI to be sent in the response.
            createdApp.setJwksURI(registrationRequest.getJwksURI());
        } catch (DCRMException ex) {
            // Delete the OAuth app created. This will also remove the registered SP for the OAuth app.
            deleteApplication(createdApp.getOauthConsumerKey());
            throw ex;
        }
        Application application = buildResponse(createdApp);
        application.setSoftwareStatement(registrationRequest.getSoftwareStatement());
        return application;
    }

    private Application buildResponse(OAuthConsumerAppDTO createdApp) {

        Application application = new Application();
        application.setClientName(createdApp.getApplicationName());
        application.setClientId(createdApp.getOauthConsumerKey());
        application.setClientSecret(createdApp.getOauthConsumerSecret());

        List<String> redirectUrisList = new ArrayList<>();
        redirectUrisList.add(createdApp.getCallbackUrl());
        application.setRedirectUris(redirectUrisList);

        List<String> grantTypesList = new ArrayList<>();
        if (StringUtils.isNotEmpty(createdApp.getGrantTypes())) {
            grantTypesList = Arrays.asList(createdApp.getGrantTypes().split(" "));
        }
        application.setGrantTypes(grantTypesList);
        application.setJwksURI(createdApp.getJwksURI());
        application.setTokenEndpointAuthMethod(createdApp.getTokenEndpointAuthMethod());
        application.setTokenEndpointAuthSignatureAlgorithm(createdApp.getTokenEndpointAuthSignatureAlgorithm());
        application.setSectorIdentifierURI(createdApp.getSectorIdentifierURI());
        application.setIdTokenSignatureAlgorithm(createdApp.getIdTokenSignatureAlgorithm());
        application.setIdTokenEncryptionAlgorithm(createdApp.getIdTokenEncryptionAlgorithm());
        application.setIdTokenEncryptionMethod(createdApp.getIdTokenEncryptionMethod());
        application.setRequestObjectSignatureValidationEnabled(createdApp.isRequestObjectSignatureValidationEnabled());
        application.setRequestObjectSignatureAlgorithm(createdApp.getRequestObjectSignatureAlgorithm());
        application.setTlsClientAuthSubjectDN(createdApp.getTlsClientAuthSubjectDN());
        application.setSubjectType(createdApp.getSubjectType());
        application.setRequestObjectEncryptionAlgorithm(createdApp.getRequestObjectEncryptionAlgorithm());
        application.setRequestObjectEncryptionMethod(createdApp.getRequestObjectEncryptionMethod());
        application.setRequirePushedAuthorizationRequests(createdApp.getRequirePushedAuthorizationRequests());
        if (OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER.equals(createdApp.getTokenBindingType())) {
            application.setTlsClientCertificateBoundAccessTokens(true);
        }
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
                throw DCRMUtils
                        .generateClientException(DCRMConstants.ErrorMessages.BAD_REQUEST_CLIENT_ID_VIOLATES_PATTERN,
                                clientIdRegex);
            }
        }

        if (StringUtils.isNotEmpty(registrationRequest.getConsumerSecret())) {
            oAuthConsumerApp.setOauthConsumerSecret(registrationRequest.getConsumerSecret());
        }
        if (registrationRequest.getExtApplicationTokenLifetime() != null) {
            oAuthConsumerApp.setApplicationAccessTokenExpiryTime(registrationRequest.getExtApplicationTokenLifetime());
        }
        if (registrationRequest.getExtUserTokenLifetime() != null) {
            oAuthConsumerApp.setUserAccessTokenExpiryTime(registrationRequest.getExtUserTokenLifetime());
        }
        if (registrationRequest.getExtRefreshTokenLifetime() != null) {
            oAuthConsumerApp.setRefreshTokenExpiryTime(registrationRequest.getExtRefreshTokenLifetime());
        }
        if (registrationRequest.getExtIdTokenLifetime() != null) {
            oAuthConsumerApp.setIdTokenExpiryTime(registrationRequest.getExtIdTokenLifetime());
        }
        if (registrationRequest.getTokenEndpointAuthMethod() != null) {
            oAuthConsumerApp.setTokenEndpointAuthMethod(registrationRequest.getTokenEndpointAuthMethod());
        }
        if (registrationRequest.getTokenEndpointAuthSignatureAlgorithm() != null) {
            oAuthConsumerApp.setTokenEndpointAuthSignatureAlgorithm
                    (registrationRequest.getTokenEndpointAuthSignatureAlgorithm());
        }
        if (registrationRequest.getSectorIdentifierURI() != null) {
            oAuthConsumerApp.setSectorIdentifierURI(registrationRequest.getSectorIdentifierURI());
        }
        if (registrationRequest.getIdTokenSignatureAlgorithm() != null) {
            oAuthConsumerApp.setIdTokenSignatureAlgorithm(registrationRequest.getIdTokenSignatureAlgorithm());
        }
        if (registrationRequest.getIdTokenEncryptionAlgorithm() != null) {
            oAuthConsumerApp.setIdTokenEncryptionAlgorithm(registrationRequest.getIdTokenEncryptionAlgorithm());
            oAuthConsumerApp.setIdTokenEncryptionEnabled(true);
        }
        if (registrationRequest.getIdTokenEncryptionMethod() != null) {
            oAuthConsumerApp.setIdTokenEncryptionMethod(registrationRequest.getIdTokenEncryptionMethod());
        }
        if (registrationRequest.getRequestObjectSignatureAlgorithm() != null) {
            oAuthConsumerApp.setRequestObjectSignatureAlgorithm(
                    (registrationRequest.getRequestObjectSignatureAlgorithm()));
        }
        if (registrationRequest.getTlsClientAuthSubjectDN() != null) {
            oAuthConsumerApp.setTlsClientAuthSubjectDN(registrationRequest.getTlsClientAuthSubjectDN());
        }
        if (registrationRequest.getSubjectType() != null) {
            oAuthConsumerApp.setSubjectType(registrationRequest.getSubjectType());
        }
        if (registrationRequest.getRequestObjectEncryptionAlgorithm() != null) {
            oAuthConsumerApp.setRequestObjectEncryptionAlgorithm
                    (registrationRequest.getRequestObjectEncryptionAlgorithm());
        }
        if (registrationRequest.getRequestObjectEncryptionMethod() != null) {
            oAuthConsumerApp.setRequestObjectEncryptionMethod(registrationRequest.getRequestObjectEncryptionMethod());
        }
        oAuthConsumerApp.setRequestObjectSignatureValidationEnabled(registrationRequest.isRequireSignedRequestObject());
        oAuthConsumerApp.setRequirePushedAuthorizationRequests(
                registrationRequest.isRequirePushedAuthorizationRequests());
        if (registrationRequest.isTlsClientCertificateBoundAccessTokens()) {
            boolean isCertificateTokenBinderAvailable = DCRDataHolder.getInstance().getTokenBinders().stream()
                    .anyMatch(t -> OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER
                            .equals(t.getBindingType()));
            if (isCertificateTokenBinderAvailable) {
                oAuthConsumerApp.setTokenBindingType(OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER);
                oAuthConsumerApp.setTokenBindingValidationEnabled(true);
            }
        }
        oAuthConsumerApp.setPkceMandatory(registrationRequest.isExtPkceMandatory());
        oAuthConsumerApp.setPkceSupportPlain(registrationRequest.isExtPkceSupportPlain());
        oAuthConsumerApp.setBypassClientCredentials(registrationRequest.isExtPublicClient());
        boolean enableFAPI = Boolean.parseBoolean(IdentityUtil.getProperty(OAuthConstants.ENABLE_FAPI));
        if (enableFAPI) {
            boolean enableFAPIDCR = Boolean.parseBoolean(IdentityUtil.getProperty(
                    OAuthConstants.ENABLE_DCR_FAPI_ENFORCEMENT));
            if (enableFAPIDCR) {
                // Add FAPI conformant property to Oauth application.
                oAuthConsumerApp.setFapiConformanceEnabled(true);
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Creating OAuth Application: " + spName + " in tenant: " + tenantDomain);
        }

        OAuthConsumerAppDTO createdApp;
        try {
            createdApp = oAuthAdminService.registerAndRetrieveOAuthApplicationData(oAuthConsumerApp);
        } catch (IdentityOAuthClientException e) {
            throw new DCRMClientException(DCRMConstants.ErrorCodes.INVALID_CLIENT_METADATA, e.getMessage(), e);
        } catch (IdentityOAuthAdminException e) {
            throw DCRMUtils.generateServerException(
                    DCRMConstants.ErrorMessages.FAILED_TO_REGISTER_APPLICATION, spName, e);
        }

        if (log.isDebugEnabled()) {
            log.debug("Created OAuth Application: " + spName + " in tenant: " + tenantDomain);
        }

        if (createdApp == null) {
            throw DCRMUtils.generateServerException(DCRMConstants.ErrorMessages.FAILED_TO_REGISTER_APPLICATION, spName);
        }
        return createdApp;
    }

    private ServiceProvider createServiceProvider(String applicationOwner, String tenantDomain, String spName,
                                                  String templateName, boolean isManagementApp) throws DCRMException {
        // Create the Service Provider
        ServiceProvider sp = new ServiceProvider();
        sp.setApplicationName(spName);
        User user = new User();
        user.setUserName(applicationOwner);
        user.setTenantDomain(tenantDomain);
        sp.setOwner(user);
        sp.setDescription("Service Provider for application " + spName);
        sp.setManagementApp(isManagementApp);

        Map<String, Object> spProperties = new HashMap<>();
        spProperties.put(OAuthConstants.IS_THIRD_PARTY_APP, true);
        addSPProperties(spProperties, sp);

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
            log.error(
                    "Error while retrieving service provider: " + serviceProviderName + " in tenant: " + tenantDomain);
        }

        return serviceProvider != null;
    }

    /**
     * Check whether the provided client id is exists.
     *
     * @param clientId client id.
     * @return true if application exists with the client id.
     * @throws DCRMException in case of failure.
     */
    private boolean isClientIdExist(String clientId) throws DCRMException {

        try {
            OAuthConsumerAppDTO dto = oAuthAdminService.getOAuthApplicationData(clientId);
            return dto != null && StringUtils.isNotBlank(dto.getApplicationName());
        } catch (IdentityOAuthAdminException e) {
            if (e.getCause() instanceof InvalidOAuthClientException) {
                return false;
            }
            throw DCRMUtils
                    .generateServerException(DCRMConstants.ErrorMessages.FAILED_TO_GET_APPLICATION_BY_ID, clientId, e);
        }
    }

    private ServiceProvider getServiceProvider(String applicationName, String tenantDomain) throws DCRMException {

        ServiceProvider serviceProvider = null;
        try {
            serviceProvider = DCRDataHolder.getInstance().getApplicationManagementService()
                    .getServiceProvider(applicationName, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw DCRMUtils.generateServerException(
                    DCRMConstants.ErrorMessages.FAILED_TO_GET_SP, applicationName, e);
        }
        return serviceProvider;
    }

    private void updateServiceProvider(ServiceProvider serviceProvider, String tenantDomain, String userName)
            throws DCRMException {

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
            throw DCRMUtils
                    .generateServerException(DCRMConstants.ErrorMessages.FAILED_TO_DELETE_SP, applicationName, e);
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

    protected String createRegexPattern(List<String> redirectURIs) throws DCRMException {

        String regexPattern = "";
        List<String> escapedUrls = new ArrayList<>();
        for (String redirectURI : redirectURIs) {
            if (DCRMUtils.isRedirectionUriValid(redirectURI)) {
                escapedUrls.add(escapeQueryParamsIfPresent(redirectURI));
            } else {
                throw DCRMUtils.generateClientException(
                        DCRMConstants.ErrorMessages.BAD_REQUEST_INVALID_REDIRECT_URI, redirectURI);
            }
        }
        if (!escapedUrls.isEmpty()) {
            regexPattern = ("(".concat(StringUtils.join(escapedUrls, "|"))).concat(")");
        }
        return regexPattern;
    }

    /**
     * Method to escape query parameters in the redirect urls.
     *
     * @param redirectURI
     * @return
     */
    private String escapeQueryParamsIfPresent(String redirectURI) {

        return redirectURI.replaceFirst("\\?", "\\\\?");
    }

    private boolean isUserAuthorized(String clientId) throws DCRMServerException {

        try {
            String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            String spName = DCRDataHolder.getInstance().getApplicationManagementService()
                    .getServiceProviderNameByClientId(clientId, DCRMConstants.OAUTH2, tenantDomain);
            String threadLocalUserName = CarbonContext.getThreadLocalCarbonContext().getUsername();
            return ApplicationMgtUtil.isUserAuthorized(spName, threadLocalUserName);
        } catch (IdentityApplicationManagementException e) {
            throw DCRMUtils.generateServerException(
                    DCRMConstants.ErrorMessages.FAILED_TO_GET_APPLICATION_BY_ID, clientId, e);
        }
    }

    /**
     * Validate client id according to the regex.
     *
     * @param clientId
     * @param clientIdValidatorRegex
     * @return validated or not
     */
    private static boolean clientIdMatchesRegex(String clientId, String clientIdValidatorRegex) {

        if (clientIdRegexPattern == null) {
            clientIdRegexPattern = Pattern.compile(clientIdValidatorRegex);
        }
        return clientIdRegexPattern.matcher(clientId).matches();
    }

    /**
     * Validates whether the tenant domain in the request matches with the application tenant domain.
     *
     * @param clientId Consumer key of application.
     * @throws DCRMException DCRMException
     */
    private void validateRequestTenantDomain(String clientId) throws DCRMException {

        try {
            String tenantDomainOfApp = OAuth2Util.getTenantDomainOfOauthApp(clientId);
            OAuth2Util.validateRequestTenantDomain(tenantDomainOfApp);
        } catch (InvalidOAuthClientException e) {
            throw new DCRMClientException(DCRMConstants.ErrorMessages.TENANT_DOMAIN_MISMATCH.getErrorCode(),
                    String.format(DCRMConstants.ErrorMessages.TENANT_DOMAIN_MISMATCH.getMessage(), clientId));
        } catch (IdentityOAuth2Exception e) {
            throw new DCRMServerException(String.format(DCRMConstants.ErrorMessages.FAILED_TO_VALIDATE_TENANT_DOMAIN
                    .getMessage(), clientId));
        }
    }

    /**
     * Create a deep copy of the input Service Provider.
     *
     * @param serviceProvider Service Provider.
     * @return Clone of serviceProvider.
     */
    private ServiceProvider cloneServiceProvider(ServiceProvider serviceProvider) {

        Gson gson = new Gson();
        ServiceProvider clonedServiceProvider = gson.fromJson(gson.toJson(serviceProvider), ServiceProvider.class);
        return clonedServiceProvider;
    }

    /**
     * Validate SSA signature using jwks_uri.
     * @param softwareStatement Software Statement
     * @throws DCRMClientException
     * @throws IdentityOAuth2Exception
     */
    private void validateSSASignature(String softwareStatement) throws DCRMClientException, IdentityOAuth2Exception {

        String jwksURL = IdentityUtil.getProperty(SSA_VALIDATION_JWKS);
        if (StringUtils.isNotEmpty(jwksURL)) {
            try {
                SignedJWT signedJWT = SignedJWT.parse(softwareStatement);
                if (!JWTSignatureValidationUtils.validateUsingJWKSUri(signedJWT, jwksURL)) {
                    throw new DCRMClientException(DCRMConstants.ErrorCodes.INVALID_SOFTWARE_STATEMENT,
                            DCRMConstants.ErrorMessages.SIGNATURE_VALIDATION_FAILED.getMessage());
                }
            } catch (ParseException e) {
                throw new DCRMClientException(DCRMConstants.ErrorCodes.INVALID_SOFTWARE_STATEMENT,
                        DCRMConstants.ErrorMessages.SIGNATURE_VALIDATION_FAILED.getMessage(), e);
            }

        } else {
            log.debug("Skipping Software Statement signature validation as jwks_uri is not configured.");
        }
    }

    /**
     * Add the properties to the service provider.
     * @param spProperties Map of property name and values to be added.
     * @param serviceProvider ServiceProvider object.
     */
    private void addSPProperties(Map<String, Object> spProperties, ServiceProvider serviceProvider) {

        ServiceProviderProperty[] serviceProviderProperties = serviceProvider.getSpProperties();
        for (Map.Entry<String, Object> entry : spProperties.entrySet()) {
            boolean propertyExists = Arrays.stream(serviceProviderProperties)
                    .anyMatch(property -> property.getName().equals(entry.getKey()));
            if (!propertyExists) {
                ServiceProviderProperty serviceProviderProperty = new ServiceProviderProperty();
                serviceProviderProperty.setName(entry.getKey());
                serviceProviderProperty.setValue(entry.getValue().toString());
                serviceProviderProperties = (ServiceProviderProperty[]) ArrayUtils.add(serviceProviderProperties,
                        serviceProviderProperty);
            }
        }
        serviceProvider.setSpProperties(serviceProviderProperties);
    }
}
