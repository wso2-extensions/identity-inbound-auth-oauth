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

package org.wso2.carbon.identity.oauth2.dcr.endpoint.util;

import org.apache.commons.logging.Log;
import org.slf4j.MDC;
import org.wso2.carbon.identity.oauth.dcr.DCRMConstants;
import org.wso2.carbon.identity.oauth.dcr.bean.Application;
import org.wso2.carbon.identity.oauth.dcr.bean.ApplicationRegistrationRequest;
import org.wso2.carbon.identity.oauth.dcr.bean.ApplicationUpdateRequest;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMException;
import org.wso2.carbon.identity.oauth.dcr.service.DCRMService;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.ApplicationDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.ErrorDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.RegistrationRequestDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.UpdateRequestDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.exceptions.DCRMEndpointException;

import javax.ws.rs.core.Response;

/**
 * This class holds Utils for DCRM endpoint component.
 */
public class DCRMUtils {

    private static final String CONFLICT_STATUS = "CONFLICT_";
    private static final String BAD_REQUEST_STATUS = "BAD_REQUEST_";
    private static final String NOT_FOUND_STATUS = "NOT_FOUND_";
    private static final String FORBIDDEN_STATUS = "FORBIDDEN_";

    private static DCRMService oAuth2DCRMService;

    public static void setOAuth2DCRMService(DCRMService oAuth2DCRMService) {

        DCRMUtils.oAuth2DCRMService = oAuth2DCRMService;
    }

    public static DCRMService getOAuth2DCRMService() {

        return oAuth2DCRMService;
    }

    public static ApplicationRegistrationRequest getApplicationRegistrationRequest(
            RegistrationRequestDTO registrationRequestDTO) {

        ApplicationRegistrationRequest appRegistrationRequest = new ApplicationRegistrationRequest();
        appRegistrationRequest.setClientName(registrationRequestDTO.getClientName());
        appRegistrationRequest.setRedirectUris(registrationRequestDTO.getRedirectUris());
        appRegistrationRequest.setGrantTypes(registrationRequestDTO.getGrantTypes());
        appRegistrationRequest.setTokenType(registrationRequestDTO.getTokenType());
        appRegistrationRequest.setConsumerKey(registrationRequestDTO.getClientId());
        appRegistrationRequest.setConsumerSecret(registrationRequestDTO.getClientSecret());
        appRegistrationRequest.setSpTemplateName(registrationRequestDTO.getSpTemplateName());
        appRegistrationRequest.setBackchannelLogoutUri(registrationRequestDTO.getBackchannelLogoutUri());
        appRegistrationRequest.setIsManagementApp(registrationRequestDTO.isManagementApp());
        appRegistrationRequest.setExtApplicationDisplayName(registrationRequestDTO.getExtApplicationDisplayName());
        appRegistrationRequest.setExtApplicationOwner(registrationRequestDTO.getExtApplicationOwner());
        appRegistrationRequest.setExtApplicationTokenLifetime(registrationRequestDTO.getExtApplicationTokenLifetime());
        appRegistrationRequest.setExtUserTokenLifetime(registrationRequestDTO.getExtUserTokenLifetime());
        appRegistrationRequest.setExtRefreshTokenLifetime(registrationRequestDTO.getExtRefreshTokenLifetime());
        appRegistrationRequest.setExtIdTokenLifetime(registrationRequestDTO.getExtIdTokenLifetime());
        appRegistrationRequest.setExtPkceMandatory(registrationRequestDTO.getExtPkceMandatory());
        appRegistrationRequest.setExtPkceSupportPlain(registrationRequestDTO.getExtPkceSupportPlain());
        appRegistrationRequest.setExtPublicClient(registrationRequestDTO.getExtPublicClient());
        appRegistrationRequest.setExtTokenType(registrationRequestDTO.getExtTokenType());
        appRegistrationRequest.setJwksURI(registrationRequestDTO.getJwksUri());
        appRegistrationRequest.setTokenEndpointAuthMethod(registrationRequestDTO.getTokenEndpointAuthMethod());
        appRegistrationRequest.setTokenEndpointAllowReusePvtKeyJwt(registrationRequestDTO
                .isTokenEndpointAllowReusePvtKeyJwt());
        appRegistrationRequest.setTokenEndpointAuthSignatureAlgorithm
                (registrationRequestDTO.getTokenEndpointAuthSigningAlg());
        appRegistrationRequest.setSectorIdentifierURI(registrationRequestDTO.getSectorIdentifierUri());
        appRegistrationRequest.setIdTokenSignatureAlgorithm(registrationRequestDTO.getIdTokenSignedResponseAlg());
        appRegistrationRequest.setIdTokenEncryptionAlgorithm(registrationRequestDTO.getIdTokenEncryptedResponseAlg());
        appRegistrationRequest.setIdTokenEncryptionMethod(registrationRequestDTO.getIdTokenEncryptedResponseEnc());
        appRegistrationRequest.setRequestObjectSignatureAlgorithm(registrationRequestDTO.getRequestObjectSigningAlg());
        appRegistrationRequest.setRequestObjectEncryptionAlgorithm
                (registrationRequestDTO.getRequestObjectEncryptionAlgorithm());
        appRegistrationRequest.setRequestObjectEncryptionMethod
                (registrationRequestDTO.getRequestObjectEncryptionMethod());
        appRegistrationRequest.setTlsClientAuthSubjectDN(registrationRequestDTO.getTlsClientAuthSubjectDn());
        appRegistrationRequest.setRequirePushedAuthorizationRequests
                (registrationRequestDTO.isRequirePushAuthorizationRequest());
        appRegistrationRequest.setRequireSignedRequestObject(registrationRequestDTO.isRequireSignedRequestObject());
        appRegistrationRequest.setTlsClientCertificateBoundAccessTokens
                (registrationRequestDTO.isTlsClientCertificateBoundAccessToken());
        appRegistrationRequest.setSubjectType(registrationRequestDTO.getSubjectType());
        appRegistrationRequest.setSoftwareStatement(registrationRequestDTO.getSoftwareStatement());
        appRegistrationRequest.setAdditionalAttributes(registrationRequestDTO.getAdditionalAttributes());
        return appRegistrationRequest;

    }

    public static ApplicationUpdateRequest getApplicationUpdateRequest(UpdateRequestDTO updateRequestDTO) {

        ApplicationUpdateRequest applicationUpdateRequest = new ApplicationUpdateRequest();
        applicationUpdateRequest.setClientName(updateRequestDTO.getClientName());
        applicationUpdateRequest.setRedirectUris(updateRequestDTO.getRedirectUris());
        applicationUpdateRequest.setGrantTypes(updateRequestDTO.getGrantTypes());
        applicationUpdateRequest.setTokenType(updateRequestDTO.getTokenType());
        applicationUpdateRequest.setBackchannelLogoutUri(updateRequestDTO.getBackchannelLogoutUri());
        applicationUpdateRequest.setExtApplicationDisplayName(updateRequestDTO.getExtApplicationDisplayName());
        applicationUpdateRequest.setExtApplicationOwner(updateRequestDTO.getExtApplicationOwner());
        applicationUpdateRequest.setExtApplicationTokenLifetime(updateRequestDTO.getExtApplicationTokenLifetime());
        applicationUpdateRequest.setExtUserTokenLifetime(updateRequestDTO.getExtUserTokenLifetime());
        applicationUpdateRequest.setExtRefreshTokenLifetime(updateRequestDTO.getExtRefreshTokenLifetime());
        applicationUpdateRequest.setExtIdTokenLifetime(updateRequestDTO.getExtIdTokenLifetime());
        applicationUpdateRequest.setExtPkceMandatory(updateRequestDTO.getExtPkceMandatory());
        applicationUpdateRequest.setExtPkceSupportPlain(updateRequestDTO.getExtPkceSupportPlain());
        applicationUpdateRequest.setExtPublicClient(updateRequestDTO.getExtPublicClient());
        applicationUpdateRequest.setExtTokenType(updateRequestDTO.getExtTokenType());
        applicationUpdateRequest.setJwksURI(updateRequestDTO.getJwksUri());
        applicationUpdateRequest.setTokenEndpointAuthMethod(updateRequestDTO.getTokenEndpointAuthMethod());
        applicationUpdateRequest.setTokenEndpointAllowReusePvtKeyJwt(
                updateRequestDTO.isTokenEndpointAllowReusePvtKeyJwt());
        applicationUpdateRequest.setTokenEndpointAuthSignatureAlgorithm
                (updateRequestDTO.getTokenEndpointAuthSigningAlg());
        applicationUpdateRequest.setSectorIdentifierURI(updateRequestDTO.getSectorIdentifierUri());
        applicationUpdateRequest.setIdTokenSignatureAlgorithm(updateRequestDTO.getIdTokenSignedResponseAlg());
        applicationUpdateRequest.setIdTokenEncryptionAlgorithm(updateRequestDTO.getIdTokenEncryptedResponseAlg());
        applicationUpdateRequest.setIdTokenEncryptionMethod(updateRequestDTO.getIdTokenEncryptedResponseEnc());
        applicationUpdateRequest.setRequestObjectSignatureAlgorithm(
                updateRequestDTO.getRequestObjectSigningAlg());
        applicationUpdateRequest.setRequestObjectEncryptionAlgorithm(
                updateRequestDTO.getRequestObjectEncryptionAlgorithm());
        applicationUpdateRequest.setRequestObjectEncryptionMethod(updateRequestDTO.getRequestObjectEncryptionMethod());
        applicationUpdateRequest.setTlsClientAuthSubjectDN(updateRequestDTO.getTlsClientAuthSubjectDn());
        applicationUpdateRequest.setRequirePushedAuthorizationRequests(updateRequestDTO.isRequireSignedRequestObject());
        applicationUpdateRequest.setRequireSignedRequestObject(updateRequestDTO.isRequireSignedRequestObject());
        applicationUpdateRequest.setTlsClientCertificateBoundAccessTokens
                (updateRequestDTO.isTlsClientCertificateBoundAccessToken());
        applicationUpdateRequest.setSubjectType(updateRequestDTO.getSubjectType());
        applicationUpdateRequest.setSoftwareStatement(updateRequestDTO.getSoftwareStatement());
        applicationUpdateRequest.setAdditionalAttributes(updateRequestDTO.getAdditionalAttributes());
        return applicationUpdateRequest;
    }

    public static void handleErrorResponse(DCRMException dcrmException, Log log) throws DCRMEndpointException {

        String errorCode = dcrmException.getErrorCode();
        Response.Status status = Response.Status.INTERNAL_SERVER_ERROR;
        boolean isStatusOnly = true;
        if (errorCode != null) {
            if (errorCode.startsWith(CONFLICT_STATUS)) {
                status = Response.Status.BAD_REQUEST;
                isStatusOnly = false;
            } else if (errorCode.startsWith(BAD_REQUEST_STATUS)) {
                status = Response.Status.BAD_REQUEST;
                isStatusOnly = false;
            } else if (errorCode.startsWith(NOT_FOUND_STATUS)) {
                status = Response.Status.UNAUTHORIZED;
            } else if (errorCode.startsWith(FORBIDDEN_STATUS)) {
                status = Response.Status.FORBIDDEN;
            } else if (errorCode.startsWith(DCRMConstants.ErrorCodes.INVALID_CLIENT_METADATA) ||
                    errorCode.startsWith(DCRMConstants.ErrorCodes.INVALID_SOFTWARE_STATEMENT)) {
                status = Response.Status.BAD_REQUEST;
                isStatusOnly = false;
            }
        }
        throw buildDCRMEndpointException(status, errorCode, dcrmException.getMessage(), isStatusOnly);
    }

    /**
     * Logs the error, builds a DCRMEndpointException with specified details and throws it.
     *
     * @param status    response status
     * @param throwable throwable
     * @throws DCRMEndpointException
     */
    public static void handleErrorResponse(Response.Status status, Throwable throwable,
                                           boolean isServerException, Log log)
            throws DCRMEndpointException {

        String errorCode;
        if (throwable instanceof DCRMException) {
            errorCode = ((DCRMException) throwable).getErrorCode();
        } else {
            errorCode = DCRMConstants.ErrorMessages.ERROR_CODE_UNEXPECTED.toString();
        }

        if (isServerException) {
            if (throwable == null) {
                log.error(status.getReasonPhrase());
            } else {
                log.error(status.getReasonPhrase(), throwable);
            }
        }
        throw buildDCRMEndpointException(status, errorCode, throwable == null ? "" : throwable.getMessage(),
                isServerException);
    }

    /**
     * Convert the Application object to the ApplicationDTO object.
     * @param application Instance of an @see Application class.
     * @return Instance of @see ApplicationDTO
     */
    public static ApplicationDTO getApplicationDTOFromApplication(Application application) {

        if (application == null) {
            return null;
        }

        ApplicationDTO applicationDTO = new ApplicationDTO();
        applicationDTO.setClientId(application.getClientId());
        applicationDTO.setClientName(application.getClientName());
        applicationDTO.setClientSecret(application.getClientSecret());
        applicationDTO.setRedirectUris(application.getRedirectUris());
        applicationDTO.setGrantTypes(application.getGrantTypes());
        /* Currently, we are not setting an expiration time for the client secret, hence according to the DCR
        specification we have to set the expiration time to 0.
        https://openid.net/specs/openid-connect-registration-1_0.html */
        applicationDTO.setClientSecretExpiresAt(0L);
        applicationDTO.setExtApplicationDisplayName(application.getExtApplicationDisplayName());
        applicationDTO.setExtApplicationOwner(application.getExtApplicationOwner());
        applicationDTO.setExtApplicationTokenLifetime(application.getExtApplicationTokenLifetime());
        applicationDTO.setExtUserTokenLifetime(application.getExtUserTokenLifetime());
        applicationDTO.setExtRefreshTokenLifetime(application.getExtRefreshTokenLifetime());
        applicationDTO.setExtIdTokenLifetime(application.getExtIdTokenLifetime());
        applicationDTO.setExtPkceMandatory(application.getExtPkceMandatory());
        applicationDTO.setExtPkceSupportPlain(application.getExtPkceSupportPlain());
        applicationDTO.setExtPublicClient(application.getExtPublicClient());
        applicationDTO.setTokenTypeExtension(application.getExtTokenType());
        applicationDTO.setExtTokenType(application.getExtTokenType());
        applicationDTO.setJwksUri(application.getJwksURI());
        applicationDTO.setTokenEndpointAuthMethod(application.getTokenEndpointAuthMethod());
        applicationDTO.setTokenEndpointAllowReusePvtKeyJwt(application.isTokenEndpointAllowReusePvtKeyJwt());
        applicationDTO.setTokenEndpointAuthSigningAlg(application.getTokenEndpointAuthSignatureAlgorithm());
        applicationDTO.setSectorIdentifierUri(application.getSectorIdentifierURI());
        applicationDTO.setIdTokenSignedResponseAlg(application.getIdTokenSignatureAlgorithm());
        applicationDTO.setIdTokenEncryptedResponseAlg(application.getIdTokenEncryptionAlgorithm());
        applicationDTO.setIdTokenEncryptedResponseEnc(application.getIdTokenEncryptionMethod());
        applicationDTO.setRequireSignedRequestObject(application.isRequestObjectSignatureValidationEnabled());
        applicationDTO.setRequestObjectSigningAlg(application.getRequestObjectSignatureAlgorithm());
        applicationDTO.setTlsClientAuthSubjectDn(application.getTlsClientAuthSubjectDN());
        applicationDTO.setSubjectType(application.getSubjectType());
        applicationDTO.setRequestObjectEncryptionAlgorithm(application.getRequestObjectEncryptionAlgorithm());
        applicationDTO.setRequestObjectEncryptionMethod(application.getRequestObjectEncryptionMethod());
        applicationDTO.setRequirePushAuthorizationRequest(application.isRequirePushedAuthorizationRequests());
        applicationDTO.setTlsClientCertificateBoundAccessToken(application.isTlsClientCertificateBoundAccessTokens());
        applicationDTO.setSoftwareStatement(application.getSoftwareStatement());
        applicationDTO.setAdditionalAttributes(application.getAdditionalAttributes());
        return applicationDTO;
    }

    /**
     * Check whether correlation id present in the log MDC.
     *
     * @return whether the correlation id is present
     */
    public static boolean isCorrelationIDPresent() {
        return MDC.get(DCRMConstants.CORRELATION_ID_MDC) != null;
    }

    /**
     * Get correlation id of current thread.
     *
     * @return correlation-id
     */
    public static String getCorrelation() {
        String ref = null;
        if (isCorrelationIDPresent()) {
            ref = MDC.get(DCRMConstants.CORRELATION_ID_MDC);
        }
        return ref;
    }

    private static DCRMEndpointException buildDCRMEndpointException(Response.Status status,
                                                                    String code, String description,
                                                                    boolean isStatusOnly) {

        if (isStatusOnly) {
            return new DCRMEndpointException(status);
        } else {
            String error = DCRMConstants.ErrorCodes.INVALID_CLIENT_METADATA;
            if (DCRMConstants.ErrorMessages.BAD_REQUEST_INVALID_REDIRECT_URI.toString().equals(code)) {
                error = DCRMConstants.ErrorCodes.INVALID_REDIRECT_URI;
            }
            if (code.equals(DCRMConstants.ErrorCodes.INVALID_SOFTWARE_STATEMENT)) {
                error = DCRMConstants.ErrorCodes.INVALID_SOFTWARE_STATEMENT;
            }

            ErrorDTO errorDTO = new ErrorDTO();
            errorDTO.setError(error);
            errorDTO.setErrorDescription(description);
            errorDTO.setRef(getCorrelation());
            return new DCRMEndpointException(status, errorDTO);
        }
    }

}
