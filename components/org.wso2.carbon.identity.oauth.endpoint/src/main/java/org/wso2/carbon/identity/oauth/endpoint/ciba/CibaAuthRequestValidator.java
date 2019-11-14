/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.ciba;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.ciba.common.CibaParams;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.ciba.util.CibaAuthUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.endpoint.exception.CibaAuthFailureException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.text.ParseException;
import java.time.ZonedDateTime;
import java.util.List;
import javax.servlet.http.HttpServletResponse;

/**
 * Handles the validation of ciba authentication request.
 */
public class CibaAuthRequestValidator {

    private static final Log log = LogFactory.getLog(CibaAuthRequestValidator.class);
    public static final String JWKS_VALIDATION_ENABLE_CONFIG = "JWTValidatorConfigs.Enable";

    private CibaAuthRequestValidator() {

    }

    private static CibaAuthRequestValidator cibaAuthRequestValidatorInstance = new CibaAuthRequestValidator();

    public static CibaAuthRequestValidator getInstance() {

        if (cibaAuthRequestValidatorInstance == null) {

            synchronized (CibaAuthRequestValidator.class) {

                if (cibaAuthRequestValidatorInstance == null) {

                    /* instance will be created at request time */
                    cibaAuthRequestValidatorInstance = new CibaAuthRequestValidator();
                }
            }
        }
        return cibaAuthRequestValidatorInstance;

    }

    /**
     * Create CIBA Authentication Error Response.
     *
     * @param request            CIBA Authentication Request.
     * @param cibaAuthRequestDTO DTO that  captures validated parameters.
     * @throws CibaAuthFailureException Ciba Authentication Failed Exception.
     */
    public void validateAuthRequestParameters(String request, CibaAuthRequestDTO cibaAuthRequestDTO)
            throws CibaAuthFailureException {

        try {

            long currentTime = ZonedDateTime.now().toInstant().toEpochMilli();
            long skewTime = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
            SignedJWT signedJWT = SignedJWT.parse(request);
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            JSONObject authRequestAsJSON = signedJWT.getJWTClaimsSet().toJSONObject();

            if (isValidSignature(signedJWT).equals(false)) {
                // Signature is invalid.
                throw new CibaAuthFailureException(HttpServletResponse.SC_UNAUTHORIZED, ErrorCodes.UNAUTHORIZED_CLIENT,
                        ErrorCodes.SubErrorCodes.INVALID_SIGNATURE);
            }

            // Validate audience of the Request.
            validateAudience(claimsSet, cibaAuthRequestDTO);

            // Validate  JWT-ID of the Request.
            validateJWTID(claimsSet, cibaAuthRequestDTO);

            // Validate the expiryTime of the Request.
            validateExpiryTime(claimsSet, cibaAuthRequestDTO, currentTime, skewTime);

            // Validate the issuedTime of the Request.
            validateIssuedTime(claimsSet, cibaAuthRequestDTO, currentTime);

            // Validate the NBF of the Request.
            validateNBF(claimsSet, cibaAuthRequestDTO, currentTime, skewTime);

            // Validate the scope of the Request.
            validateScope(authRequestAsJSON, cibaAuthRequestDTO);

            // Validate the client_notification_token of the Request.
            validateClientNotificationToken(authRequestAsJSON, cibaAuthRequestDTO);

            // Validate the client_notification_token of the Request.
            validateACRValues(authRequestAsJSON, cibaAuthRequestDTO);

            // Validate the binding_message of the Request.
            validateBindingMessage(authRequestAsJSON, cibaAuthRequestDTO);

            // Validate the transaction_context of the Request.
            validateTransactionContext(authRequestAsJSON, cibaAuthRequestDTO);

            // Validate the requested_expiry of the Request.
            validateRequestedExpiry(authRequestAsJSON, cibaAuthRequestDTO);

            if (log.isDebugEnabled()) {
                log.debug(" CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + "is properly validated.");
            }

        } catch (ParseException e) {
            throw new CibaAuthFailureException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * Checks whether the requested_expiry values exists and is valid.
     *
     * @param authRequestAsJSON  CIBA Authentication request as JSON.
     * @param cibaAuthRequestDTO DTO that captures authentication request parameters.
     * @throws CibaAuthFailureException Ciba Authentication Failed Exception.
     */
    private void validateRequestedExpiry(JSONObject authRequestAsJSON, CibaAuthRequestDTO cibaAuthRequestDTO)
            throws CibaAuthFailureException {

        // Validation for requested_expiry.

        if ((authRequestAsJSON.get(CibaParams.REQUESTED_EXPIRY)) == null) {
            //  Requested_expiry claim value does not exist.
            return;
        }

        if (StringUtils.isBlank(authRequestAsJSON.get(CibaParams.REQUESTED_EXPIRY).toString())) {
            // Requested expiry is a blank value.
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() +
                        ".The request is with invalid  value for (requested_expiry).");
            }

            throw new CibaAuthFailureException(HttpServletResponse.SC_BAD_REQUEST, ErrorCodes.INVALID_REQUEST,
                    ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
        }

        String requestedExpiryAsString = String.valueOf(authRequestAsJSON.get(CibaParams.REQUESTED_EXPIRY));
        long requestedExpiry = Long.parseLong(requestedExpiryAsString);

        if (requestedExpiry < CibaParams.MAXIMUM_REQUESTED_EXPIRY) {
            cibaAuthRequestDTO.setRequestedExpiry(requestedExpiry);
        } else {
            cibaAuthRequestDTO.setRequestedExpiry(CibaParams.MAXIMUM_REQUESTED_EXPIRY);

            if (log.isDebugEnabled()) {
                log.debug("Warning. CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + ".Requested expiry is too long." +
                        "Setting the maximum default value.");
            }
        }
    }

    /**
     * Checks whether the transaction_context values exists and is valid.
     *
     * @param authRequestAsJSON  CIBA Authentication request as JSON.
     * @param cibaAuthRequestDTO DTO that captures authentication request parameters.
     * @throws CibaAuthFailureException Ciba Authentication Failed Exception.
     */
    private void validateTransactionContext(JSONObject authRequestAsJSON, CibaAuthRequestDTO cibaAuthRequestDTO)
            throws CibaAuthFailureException {

        // Validation for transaction_context.

        if ((authRequestAsJSON.get(CibaParams.TRANSACTION_CONTEXT)) == null) {
            // Request has no transaction_context claim.
            return;
        }
        if (StringUtils.isBlank(authRequestAsJSON.get(CibaParams.TRANSACTION_CONTEXT).toString())) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + ".The request is with invalid  " +
                        "value for (transaction_context).");
            }

            throw new CibaAuthFailureException(HttpServletResponse.SC_BAD_REQUEST,
                    ErrorCodes.INVALID_REQUEST, ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
        }

        cibaAuthRequestDTO.setTransactionContext
                (String.valueOf(authRequestAsJSON.get(CibaParams.TRANSACTION_CONTEXT)));
    }

    /**
     * Checks whether the binding_message values exists and is valid.
     *
     * @param authRequestAsJSON  CIBA Authentication request as JSON.
     * @param cibaAuthRequestDTO DTO that captures authentication request parameters.
     * @throws CibaAuthFailureException Ciba Authentication Failed Exception.
     */
    private void validateBindingMessage(JSONObject authRequestAsJSON, CibaAuthRequestDTO cibaAuthRequestDTO)
            throws CibaAuthFailureException {
        // Validation for binding_message.

        if ((authRequestAsJSON.get(CibaParams.BINDING_MESSAGE)) == null) {
            // Request has claim for binding_message.
            return;
        }

        if (StringUtils.isBlank(authRequestAsJSON.get(CibaParams.BINDING_MESSAGE).toString())) {
            // Binding_message with a blank value which is not acceptable.

            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() +
                        ".The request is with invalid  value for (binding_message).");
            }
            throw new CibaAuthFailureException(HttpServletResponse.SC_BAD_REQUEST,
                    ErrorCodes.INVALID_REQUEST, ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
        }

        // Adding binding_message to CibaAuthenticationResponse after successful validation.
        cibaAuthRequestDTO.setBindingMessage(String.valueOf(authRequestAsJSON.get(CibaParams.BINDING_MESSAGE)));
    }

    /**
     * Checks whether the user_code values exists and is valid.
     *
     * @param authRequestAsJSON  CIBA Authentication request as JSON.
     * @param cibaAuthRequestDTO DTO that captures authentication request parameters.
     * @throws CibaAuthFailureException Ciba Authentication Failed Exception.
     */
    private void validateUserCode(JSONObject authRequestAsJSON, CibaAuthRequestDTO cibaAuthRequestDTO)
            throws CibaAuthFailureException {

        // Validation for user_code values.

        if ((authRequestAsJSON.get(CibaParams.USER_CODE)) != null) {
            // No claims for user_code.

            if ((StringUtils.isBlank(authRequestAsJSON.get(CibaParams.USER_CODE).toString()))) {
                // User_code with blank values.

                if (log.isDebugEnabled()) {
                    log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                            cibaAuthRequestDTO.getAudience() + ".The request is with invalid  value for (user_code).");
                }

                throw new CibaAuthFailureException(HttpServletResponse.SC_BAD_REQUEST, ErrorCodes.INVALID_REQUEST,
                        ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
            }

            // Setting the user_code to CibaAuthenticationResponse after validation.
            cibaAuthRequestDTO.setUserCode(String.valueOf(authRequestAsJSON.get(CibaParams.USER_CODE)));
        }
    }

    /**
     * Checks whether the ACR values exists and is valid.
     *
     * @param authRequestAsJSON  CIBA Authentication request as JSON.
     * @param cibaAuthRequestDTO DTO that captures authentication request parameters.
     * @throws CibaAuthFailureException Ciba Authentication Failed Exception.
     */
    private void validateACRValues(JSONObject authRequestAsJSON, CibaAuthRequestDTO cibaAuthRequestDTO)
            throws CibaAuthFailureException {

        // Validation for acr values.

        if ((authRequestAsJSON.get(CibaParams.ACR_VALUES)) == null) {
            return;
        }

        if (StringUtils.isBlank(authRequestAsJSON.get(CibaParams.ACR_VALUES).toString())) {
            // ACR claim with blank values.
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + ".The request is with invalid  value for (acr).");
            }

            throw new CibaAuthFailureException(HttpServletResponse.SC_BAD_REQUEST, ErrorCodes.INVALID_REQUEST,
                    ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
        }

        // Setting scope to Ciba AuthenticationResponse after validation.
        cibaAuthRequestDTO.setAcrValues(String.valueOf(authRequestAsJSON.get(CibaParams.ACR_VALUES)));
    }

    /**
     * Checks whether the client_notification_token exists and is valid.
     *
     * @param authRequestAsJSON  CIBA Authentication request as JSON.
     * @param cibaAuthRequestDTO DTO that captures authentication request parameters.
     * @throws CibaAuthFailureException Ciba Authentication Failed Exception.
     */
    private void validateClientNotificationToken(JSONObject authRequestAsJSON,
                                                 CibaAuthRequestDTO cibaAuthRequestDTO)
            throws CibaAuthFailureException {

        // Validation for client_notification_token.Mandatory parameter for CIBA Authentication Request for ping mode.

        if (authRequestAsJSON.get(CibaParams.CLIENT_NOTIFICATION_TOKEN) == null) {
            // Client_notification_token does not exist.
            return;
        }

        if (StringUtils.isBlank(authRequestAsJSON.get(CibaParams.CLIENT_NOTIFICATION_TOKEN).toString())) {
            // Blank values for client_notification_token.

            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + ".The request is with invalid  value for " +
                        "(client_notification_token).");
            }

            throw new CibaAuthFailureException(HttpServletResponse.SC_BAD_REQUEST, ErrorCodes.INVALID_REQUEST,
                    ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
        }

        // Setting the client_notification_token to CibAuthenticationResponse
        cibaAuthRequestDTO.setClientNotificationToken(String.valueOf(authRequestAsJSON.
                get(CibaParams.CLIENT_NOTIFICATION_TOKEN)));
    }

    /**
     * Checks whether the scope exists and is valid.
     *
     * @param authRequestAsJSON  CIBA Authentication request as JSON.
     * @param cibaAuthRequestDTO DTO that captures authentication request parameters.
     * @throws CibaAuthFailureException Ciba Authentication Failed Exception.
     */
    private void validateScope(JSONObject authRequestAsJSON, CibaAuthRequestDTO cibaAuthRequestDTO)
            throws CibaAuthFailureException {
        // Validation for scope.Mandatory parameter for CIBA AuthenticationRequest.

        if (authRequestAsJSON.get(CibaParams.SCOPE) == null) {
            // Missing 'scope' claim in the request.
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + ".The request is missing the mandatory claim (scope).");
            }

            throw new CibaAuthFailureException(HttpServletResponse.SC_BAD_REQUEST, ErrorCodes.INVALID_REQUEST,
                    ErrorCodes.SubErrorCodes.MISSING_PARAMETERS);
        }

        if (StringUtils.isBlank(String.valueOf(authRequestAsJSON.get(CibaParams.SCOPE)))) {
            // Scope is with blank value.

            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + ".The request is with invalid  value for (scope).");
            }

            throw new CibaAuthFailureException(HttpServletResponse.SC_BAD_REQUEST, ErrorCodes.INVALID_REQUEST,
                    ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
        }

        // Setting the scope of the cibaAuthenticationResponse.
        cibaAuthRequestDTO
                .setScope(OAuth2Util.buildScopeArray(String.valueOf(authRequestAsJSON.get(CibaParams.SCOPE))));
    }

    /**
     * Checks whether the JWT-NBF is valid.
     *
     * @param claimsSet          CIBA Authentication request as claim sets for the ease.
     * @param cibaAuthRequestDTO DTO that captures authentication request parameters.
     * @throws CibaAuthFailureException Ciba Authentication Failed Exception.
     */
    private void validateNBF(JWTClaimsSet claimsSet, CibaAuthRequestDTO cibaAuthRequestDTO,
                             long currentTime, long skewTime) throws CibaAuthFailureException {
        // Validation for nbf-time before signed request is acceptable. Mandatory parameter if signed.

        if (claimsSet.getNotBeforeTime() == null) {

            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + ".The request is missing the mandatory parameter (nbf).");
            }

            throw new CibaAuthFailureException(HttpServletResponse.SC_BAD_REQUEST, ErrorCodes.INVALID_REQUEST,
                    ErrorCodes.SubErrorCodes.MISSING_PARAMETERS);
        }

        long nbfTime = claimsSet.getNotBeforeTime().getTime();

        if (checkNotBeforeTime(currentTime, nbfTime, skewTime)) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + ".The request is with invalid  value for (nbf).");
            }
            throw new CibaAuthFailureException(HttpServletResponse.SC_BAD_REQUEST, ErrorCodes.INVALID_REQUEST,
                    ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
        }

        // Setting the validated NBF after validation of the AuthenticationRequest.
        cibaAuthRequestDTO.setNotBeforeTime(nbfTime);
    }

    /**
     * Checks whether the JWT-Issued time is valid.
     *
     * @param currentTime        Current system time
     * @param claimsSet          CIBA Authentication request as claim sets for the ease.
     * @param cibaAuthRequestDTO DTO that captures authentication request parameters.
     * @throws CibaAuthFailureException Ciba Authentication Failed Exception.
     */
    private void validateIssuedTime(JWTClaimsSet claimsSet, CibaAuthRequestDTO cibaAuthRequestDTO, long currentTime)
            throws CibaAuthFailureException {

        // Validation for (iat).Mandatory parameter if signed.

        if (claimsSet.getIssueTime() == null) {
            // (iat) is a null value.
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + ".The request is missing the mandatory parameter (iat).");
            }

            throw new CibaAuthFailureException(HttpServletResponse.SC_BAD_REQUEST, ErrorCodes.INVALID_REQUEST,
                    ErrorCodes.SubErrorCodes.MISSING_PARAMETERS);
        }

        long issuedTime = claimsSet.getIssueTime().getTime();
        if (issuedTime > currentTime) {
            // Invalid issued time.Issued time is in future.
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + ".The request is with invalid value for (iat) .");
            }
            throw new CibaAuthFailureException(HttpServletResponse.SC_BAD_REQUEST, ErrorCodes.INVALID_REQUEST,
                    ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
        }

        // Setting the validated IssuedTime.
        cibaAuthRequestDTO.setIssuedTime(issuedTime);
    }

    /**
     * Checks whether the JWT-Expiry time is valid.
     *
     * @param claimsSet          CIBA Authentication request as claim sets for the ease.
     * @param cibaAuthRequestDTO DTO that captures authentication request parameters.
     * @param currentTime        CurrentTime in milliseconds.
     * @param skewTime           skewtime in milliseconds.
     * @throws CibaAuthFailureException Ciba Authentication Failed Exception.
     */
    private void validateExpiryTime(JWTClaimsSet claimsSet, CibaAuthRequestDTO cibaAuthRequestDTO,
                                    long currentTime, long skewTime) throws CibaAuthFailureException {

        // Validation for expiryTime.

        if (claimsSet.getExpirationTime() == null) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + ".The request is missing the mandatory parameter (exp).");
            }
            throw new CibaAuthFailureException(HttpServletResponse.SC_BAD_REQUEST, ErrorCodes.INVALID_REQUEST,
                    ErrorCodes.SubErrorCodes.MISSING_PARAMETERS);
        }
        long expiryTime = claimsSet.getExpirationTime().getTime();

        if (expiryTime < currentTime + skewTime) {
            // Invalid token as expired time has passed.
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + ".The provided JWT is expired.");
            }
            throw new CibaAuthFailureException(HttpServletResponse.SC_BAD_REQUEST, ErrorCodes.INVALID_REQUEST,
                    ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
        }

        // Setting the validated expiredTime of the AuthenticationRequest.
        cibaAuthRequestDTO.setExpiredTime(expiryTime);
    }

    /**
     * Checks whether the JWT-ID is valid.
     *
     * @param claimsSet          CIBA Authentication request as claim sets for the ease.
     * @param cibaAuthRequestDTO DTO that captures authentication request parameters.
     * @throws CibaAuthFailureException Ciba Authentication Failed Exception.
     */
    private void validateJWTID(JWTClaimsSet claimsSet, CibaAuthRequestDTO cibaAuthRequestDTO)
            throws CibaAuthFailureException {

        // Validation for (jti).Mandatory parameter if signed.
        if (claimsSet.getJWTID() == null) {
            // (jti) is null.
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + ".The request is missing the mandatory parameter (jti).");
            }
            throw new CibaAuthFailureException(HttpServletResponse.SC_BAD_REQUEST, ErrorCodes.INVALID_REQUEST,
                    ErrorCodes.INVALID_REQUEST);
        }

        if (StringUtils.isBlank(claimsSet.getJWTID())) {
            // (jti) is a blank value.
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + ".The request has invalid values for the parameter (jti).");
            }

            throw new CibaAuthFailureException(HttpServletResponse.SC_BAD_REQUEST, ErrorCodes.INVALID_REQUEST,
                    ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
        }

        // Set the validated value to JWT.
        cibaAuthRequestDTO.setJWTID(claimsSet.getJWTID());
    }

    /**
     * Checks whether the request is properly signed.
     *
     * @param signedJWT SignedJWT.
     * @return Boolean.
     * @throws CibaAuthFailureException Ciba Authentication Failed Exception.
     */
    private Boolean isValidSignature(SignedJWT signedJWT) throws CibaAuthFailureException {

        String alg = signedJWT.getHeader().getAlgorithm().getName();
        if (StringUtils.isEmpty(alg)) {
            throw new CibaAuthFailureException(HttpServletResponse.SC_BAD_REQUEST, ErrorCodes.INVALID_REQUEST,
                    "Algorithm must not be null.");
        }

        if (alg.startsWith("RS")) {
            throw new CibaAuthFailureException(HttpServletResponse.SC_BAD_REQUEST, ErrorCodes.INVALID_REQUEST,
                    "Algorithms not supported.");
        }
        return true;
    }

    /**
     * Checks whether the audience is valid as expected.
     *
     * @param claimsSet          CIBA Authentication request as claim sets for the ease.
     * @param cibaAuthRequestDTO DTO that captures authentication request parameters.
     * @throws CibaAuthFailureException Ciba Authentication Failed Exception.
     */
    public void validateAudience(JWTClaimsSet claimsSet, CibaAuthRequestDTO cibaAuthRequestDTO)
            throws CibaAuthFailureException {

        List<String> aud = claimsSet.getAudience();
        String clientId = cibaAuthRequestDTO.getIssuer();
        try {
            OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientId);
            String domain = OAuth2Util.getTenantDomainOfOauthApp(appDO);

            // Getting expected audience dynamically from configs.
            String expectedAudience = OAuth2Util.getIdTokenIssuer(domain);

            // Validation for aud-audience.
            if (aud.isEmpty()) {
                // No value for audience found in the request.

                if (log.isDebugEnabled()) {
                    log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                            cibaAuthRequestDTO.getAudience() +
                            ".The request is missing the mandatory parameter 'aud'.");
                }

                throw new CibaAuthFailureException(HttpServletResponse.SC_BAD_REQUEST,
                        ErrorCodes.INVALID_REQUEST, ErrorCodes.SubErrorCodes.MISSING_PARAMETERS);
            }

            // Validation for aud-audience to meet mandated value.
            if (!aud.contains(expectedAudience)) {
                // The audience value does not suit mandated value.
                if (log.isDebugEnabled()) {
                    log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                            cibaAuthRequestDTO.getAudience() + ".Invalid value for (aud).");
                }

                throw new CibaAuthFailureException(HttpServletResponse.SC_BAD_REQUEST,
                        ErrorCodes.INVALID_REQUEST, ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
            }

            // Adding issuer of the request to AuthenticationRequest after validation.
            cibaAuthRequestDTO.setAudience(expectedAudience);
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            throw new CibaAuthFailureException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * Checks whether the client is valid.
     *
     * @param request            CIBA Authentication request.
     * @param cibaAuthRequestDTO DTO that captures authentication request parameters.
     * @throws CibaAuthFailureException Ciba Authentication Failed Exception.
     */
    public void validateClient(String request, CibaAuthRequestDTO cibaAuthRequestDTO)
            throws CibaAuthFailureException {

        try {
            SignedJWT signedJWT = SignedJWT.parse(request);
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            String clientId = claimsSet.getIssuer();

            // Validate whether the claim for the issuer exists.
            if (clientId == null) {
                // ClientID does not exist.

                if (log.isDebugEnabled()) {
                    log.debug("Missing issuer of the JWT of the request : " + request);
                }

                throw new CibaAuthFailureException(HttpServletResponse.SC_UNAUTHORIZED,
                        ErrorCodes.UNAUTHORIZED_CLIENT, ErrorCodes.SubErrorCodes.MISSING_CLIENT_ID);
            }

            // Validate whether the claim for the issuer is a valid value.
            if (StringUtils.isBlank(claimsSet.getIssuer())) {
                // (iss) is a blank value.

                if (log.isDebugEnabled()) {
                    log.debug("Missing issuer of the JWT of the request : " + request);
                }

                throw new CibaAuthFailureException(HttpServletResponse.SC_UNAUTHORIZED,
                        ErrorCodes.UNAUTHORIZED_CLIENT, ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
            }

            // Validation for existence of clientApp  in the store.
            OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientId);
            String clientSecret = appDO.getOauthConsumerSecret();
            if (clientSecret == null || StringUtils.isBlank(clientSecret) || clientSecret.equals("null")) {

                if (log.isDebugEnabled()) {
                    log.debug("The request : " + request + " doesn't have a proper clientID.");
                }
                throw new CibaAuthFailureException(HttpServletResponse.SC_UNAUTHORIZED,
                        ErrorCodes.UNAUTHORIZED_CLIENT, ErrorCodes.SubErrorCodes.UNKNOWN_CLIENT);
            }

            // Set the clientID since properly validated.
            cibaAuthRequestDTO.setIssuer(clientId);

        } catch (InvalidOAuthClientException e) {
            if (log.isDebugEnabled()) {
                log.debug("The request : " + request + " doesn't have a proper clientID.");
            }
            throw new CibaAuthFailureException(HttpServletResponse.SC_UNAUTHORIZED,
                    ErrorCodes.UNAUTHORIZED_CLIENT, ErrorCodes.SubErrorCodes.UNKNOWN_CLIENT);

        } catch (IdentityOAuth2Exception | ParseException ex) {
            throw new CibaAuthFailureException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, ex.getMessage());
        }
    }

    /**
     * The JWT MAY contain an nbf (not before) claim that identifies the time before which the
     * token MUST NOT be accepted for processing.
     *
     * @param notBeforeTimeMillis Not before time
     * @param currentTimeInMillis Current time
     * @param timeStampSkewMillis Time skew
     * @return true or false
     */
    private boolean checkNotBeforeTime(long notBeforeTimeMillis, long currentTimeInMillis, long timeStampSkewMillis) {

        if (currentTimeInMillis + timeStampSkewMillis < notBeforeTimeMillis) {
            if (log.isDebugEnabled()) {
                log.error("JSON Web Token is used before Not_Before_Time." +
                        ", Not Before Time(ms) : " + notBeforeTimeMillis +
                        ", TimeStamp Skew : " + timeStampSkewMillis +
                        ", Current Time : " + currentTimeInMillis + ". JWT Rejected.");
            }
            return false;
        } else {
            return true;
        }
    }

    /**
     * Verify whether the user_code matches with the user.
     *
     * @param authRequest        CIBA Authentication request.
     * @param cibaAuthRequestDTO DTO that captures authentication request parameters.
     * @return boolean Returns whether user_code is matching with existing.
     * @throws CibaAuthFailureException Ciba Authentication Failed Exception.
     */
    public boolean isMatchingUserCode(String authRequest, CibaAuthRequestDTO cibaAuthRequestDTO)
            throws CibaAuthFailureException {

        try {
            SignedJWT signedJWT = SignedJWT.parse(authRequest);
            JSONObject authRequestAsJSON = signedJWT.getJWTClaimsSet().toJSONObject();

            // Validate user_code.
            validateUserCode(authRequestAsJSON, cibaAuthRequestDTO);

            // No implementation for the moment.Modify if needed.
            return true;

        } catch (ParseException e) {
            throw new CibaAuthFailureException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());

        } catch (CibaAuthFailureException ex) {
            throw new CibaAuthFailureException(ex.getStatus(), ex.getErrorCode(), ex.getErrorDescription());
        }
    }

    /**
     * Validation for login_hint_token,id_token_hint.
     * Anyone and exactly one is mandatory.
     *
     * @param authRequest        CIBA Authentication request.
     * @param cibaAuthRequestDTO DTO that captures authentication request parameters.
     * @throws CibaAuthFailureException Ciba Authentication Failed Exception.
     */
    public void validateUser(String authRequest, CibaAuthRequestDTO cibaAuthRequestDTO)
            throws CibaAuthFailureException {

        try {
            SignedJWT signedJWT = SignedJWT.parse(authRequest);
            JSONObject jo = signedJWT.getJWTClaimsSet().toJSONObject();

            // Validation to  check if any hints present.
            if ((jo.get(CibaParams.LOGIN_HINT_TOKEN) == null)
                    && (jo.get(CibaParams.LOGIN_HINT) == null)
                    && (jo.get(CibaParams.ID_TOKEN_HINT) == null)) {
                // All hints are null.

                if (log.isDebugEnabled()) {
                    log.debug("Invalid request. Missing mandatory parameter, 'hints' from the request : "
                            + authRequest);
                }

                throw new CibaAuthFailureException(HttpServletResponse.SC_UNAUTHORIZED,
                        ErrorCodes.UNAUTHORIZED_USER, ErrorCodes.SubErrorCodes.MISSING_USER_ID);
            }

            // Validation when login_hint_token exists.
            if (!(jo.get(CibaParams.LOGIN_HINT_TOKEN) == null)
                    && (jo.get(CibaParams.LOGIN_HINT) == null)
                    && (jo.get(CibaParams.ID_TOKEN_HINT) == null)) {

                if (log.isDebugEnabled()) {
                    log.debug("No Login_hint_token support for current version of IS.Invalid Ciba Authentication " +
                            "request : " + authRequest);
                }
                throw new CibaAuthFailureException(HttpServletResponse.SC_BAD_REQUEST,
                        ErrorCodes.INVALID_REQUEST, ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
            }

            // Validation when login_hint exists.
            if ((jo.get(CibaParams.LOGIN_HINT_TOKEN) == null)
                    && (!(jo.get(CibaParams.LOGIN_HINT) == null))
                    && (jo.get(CibaParams.ID_TOKEN_HINT) == null)) {
                // Claim exists for login_hint.

                if (StringUtils.isBlank(jo.get(CibaParams.LOGIN_HINT).toString())) {
                    // Login_hint is blank.
                    throw new CibaAuthFailureException(HttpServletResponse.SC_UNAUTHORIZED,
                            ErrorCodes.UNAUTHORIZED_USER, ErrorCodes.SubErrorCodes.MISSING_USER_ID);
                }

                if (!doesUserExist(String.valueOf(jo.get(CibaParams.LOGIN_HINT)))) {
                    // User exists in the store and setting the user hint here.
                    if (log.isDebugEnabled()) {
                        log.debug("Unknown user identity from the request : " + authRequest);
                    }
                    throw new CibaAuthFailureException(HttpServletResponse.SC_UNAUTHORIZED,
                            ErrorCodes.UNAUTHORIZED_USER, ErrorCodes.SubErrorCodes.UNKNOWN_USER);
                }

                // User exists in the store and setting the user hint here
                cibaAuthRequestDTO.setUserHint(String.valueOf(jo.get(CibaParams.LOGIN_HINT)));
                return;
            }

            // Validation when id_token_hint exists.
            if ((jo.get(CibaParams.LOGIN_HINT_TOKEN) == null)
                    && (jo.get(CibaParams.LOGIN_HINT) == null)
                    && (!(jo.get(CibaParams.ID_TOKEN_HINT) == null))) {
                // Value exists for id_token_hint

                if (StringUtils.isBlank(jo.get(CibaParams.ID_TOKEN_HINT).toString())) {
                    // Existing values for id_token_hint are blank.
                    if (log.isDebugEnabled()) {
                        log.debug("Unknown user identity from the request " + authRequest);
                    }

                    throw new CibaAuthFailureException(HttpServletResponse.SC_UNAUTHORIZED,
                            ErrorCodes.UNAUTHORIZED_USER, ErrorCodes.SubErrorCodes.MISSING_USER_ID);
                }

                if (!OAuth2Util.validateIdToken(String.valueOf(jo.get(CibaParams.ID_TOKEN_HINT)))) {
                    // Provided id_token_hint is not valid.
                    if (log.isDebugEnabled()) {
                        log.debug("Invalid id_token_hint from the request " + authRequest);
                    }

                    throw new CibaAuthFailureException(HttpServletResponse.SC_UNAUTHORIZED,
                            ErrorCodes.UNAUTHORIZED_USER, ErrorCodes.SubErrorCodes.INVALID_ID_TOKEN_HINT);
                }

                if (!doesUserExist(getUserfromIDToken(String.valueOf(jo.get(CibaParams.ID_TOKEN_HINT))))) {
                    // User does not exist in store.
                    if (log.isDebugEnabled()) {
                        log.debug("Unknown user identity from the request " + authRequest);
                    }

                    throw new CibaAuthFailureException(HttpServletResponse.SC_UNAUTHORIZED,
                            ErrorCodes.UNAUTHORIZED_USER, ErrorCodes.SubErrorCodes.UNKNOWN_USER);
                }

                // Adding user_hint to the CIBA authentication request after successful validation.
                cibaAuthRequestDTO.setUserHint(getUserfromIDToken(String.valueOf(jo.get(CibaParams.ID_TOKEN_HINT))));
            }

        } catch (ParseException ex) {
            throw new CibaAuthFailureException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, ex.getMessage());
        }
    }

    /**
     * Verify whether the mentioned user exists.
     *
     * @param userHint Carries user identity.
     * @return boolean Returns whether user exists in the store or not.
     * @throws CibaAuthFailureException Ciba Authentication Failed Exception.
     */
    private boolean doesUserExist(String userHint) throws CibaAuthFailureException {
        // Check whether given user exists in the store.Only username is supported as user_hint.
        try {
            if (log.isDebugEnabled()) {
                log.debug("Checking whether user exists in the store for the user id " + userHint);
            }

            // Getting the tenantID of user - tenant in which he is registered in.
            int tenantID = OAuth2Util.getTenantIdFromUserName(userHint);

            // Checking with realm service whether user exists.
            return CibaAuthUtil.isUserExists(tenantID, userHint);

        } catch (CibaCoreException | IdentityOAuth2Exception e) {

            throw new CibaAuthFailureException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * Obtain sub from given id token.
     *
     * @param idTokenHint it carries user identity
     * @return String- the user identity
     * @throws CibaAuthFailureException Ciba Authentication Failed Exception.
     */
    private String getUserfromIDToken(String idTokenHint) throws CibaAuthFailureException {
        // Obtain (sub) from id_token_hint
        try {
            if (log.isDebugEnabled()) {
                log.info("Extracting 'sub' from this id_token_hint " + idTokenHint);
            }
            SignedJWT signedJWT = SignedJWT.parse(idTokenHint);
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            return claimsSet.getSubject();

        } catch (ParseException e) {
            throw new CibaAuthFailureException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * Validate whether Request JWT is in proper formatting.
     *
     * @param authRequest Ciba Authentication Request as a String.
     * @throws CibaAuthFailureException Ciba Authentication Failed Exception.
     */
    public void validateRequest(String authRequest) throws CibaAuthFailureException {

        try {

            // The assertion is not an encrypted one.
            SignedJWT signedJWT = SignedJWT.parse(authRequest);

            Payload payload = signedJWT.getPayload();
            Base64URL signature = signedJWT.getSignature();
            JWSHeader header = signedJWT.getHeader();

            if (payload == null || header == null || signature == null) {
                throw new CibaAuthFailureException(HttpServletResponse.SC_BAD_REQUEST, ErrorCodes.INVALID_REQUEST,
                        "Missing components(header,payload or signature) of JWT ");
            }

            if (log.isDebugEnabled()) {
                log.debug("The JWT is signed. Claim set of the signed JWT is obtainable.");
                log.debug("JWT Header: " + signedJWT.getHeader().toJSONObject().toString());
                log.debug("JWT Payload: " + signedJWT.getPayload().toJSONObject().toString());
                log.debug("Signature: " + signedJWT.getSignature().toString());
            }

            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            if (claimsSet == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Claim values are empty in the given JSON Web Token");
                }
                throw new CibaAuthFailureException(HttpServletResponse.SC_BAD_REQUEST, ErrorCodes.INVALID_REQUEST,
                        ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
            }

        } catch (ParseException e) {
            String errorMessage =
                    "Unexpected number of Base64URL parts of the nested JWT payload. Expected number" +
                            " of parts must be three. ";
            throw new CibaAuthFailureException(HttpServletResponse.SC_BAD_REQUEST, ErrorCodes.INVALID_REQUEST,
                    errorMessage);
        }
    }
}
