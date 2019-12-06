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
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeRequest;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.endpoint.exception.CibaAuthFailureException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.model.Constants;

import java.text.ParseException;
import java.util.Calendar;
import java.util.List;
import java.util.TimeZone;

/**
 * Handles the validation of ciba authentication request.
 */
public class CibaAuthRequestValidator {

    private static final Log log = LogFactory.getLog(CibaAuthRequestValidator.class);

    /**
     * Validate CIBA Authentication Request.
     *
     * @param request CIBA Authentication Request.
     * @throws CibaAuthFailureException CIBA Authentication Failed Exception.
     * @throws CibaAuthFailureException CIBA server serror.
     */
    public void validateAuthRequestParams(String request) throws CibaAuthFailureException {

        try {
            long timeInMillis = Calendar.getInstance(TimeZone.getTimeZone(CibaConstants.UTC)).getTimeInMillis();
            long skewTime = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() *
                    CibaConstants.SEC_TO_MILLISEC_FACTOR;
            SignedJWT signedJWT = SignedJWT.parse(request);
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

            if (!isValidSignature(signedJWT)) {
                // Signature is invalid.
                throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST, "Invalid signature.");
            }

            // Validate audience of the Request.
            validateAudience(claimsSet);

            // Validate  JWT-ID of the Request.
            validateJti(claimsSet);

            // Validate the expiryTime of the Request.
            validateExpiryTime(claimsSet, timeInMillis, skewTime);

            // Validate the issuedTime of the Request.
            validateIssuedTime(claimsSet, timeInMillis);

            // Validate the NBF of the Request.
            validateNBF(claimsSet, timeInMillis, skewTime);

            // Validate the scope of the Request.
            validateScopes(claimsSet);

            // Validate the client_notification_token of the Request.
            validateACR(claimsSet);

            // Validate the binding_message of the Request.
            validateBindingMessage(claimsSet);

            // Validate the transaction_context of the Request.
            valiateTransactionContext(claimsSet);

            // Validate the requested_expiry of the Request.
            validateRequestedExpiry(claimsSet);

            if (log.isDebugEnabled()) {
                log.debug(" CIBA Authentication Request made by client with clientID : " +
                        claimsSet.getIssuer() + "is properly validated.");
            }

        } catch (ParseException e) {
            throw new CibaAuthFailureException(OAuth2ErrorCodes.SERVER_ERROR,
                    "Error in validating authentication request.", e);
        }
    }

    /**
     * Checks whether the requested_expiry values exists and is valid.
     *
     * @param claimsSet JWT claimsets of the authentication request.
     * @throws CibaAuthFailureException CIBA Authentication Failed Server Exception.
     */
    private void validateRequestedExpiry(JWTClaimsSet claimsSet) throws CibaAuthFailureException {

        // Validation for requested_expiry.
        if ((claimsSet.getClaim(CibaConstants.REQUESTED_EXPIRY)) == null) {
            //  Requested_expiry claim value does not exist.
            return;
        }
        if (StringUtils.isBlank(String.valueOf(claimsSet.getClaim(CibaConstants.REQUESTED_EXPIRY)))) {
            // Requested expiry is a blank value.
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        claimsSet.getIssuer() + " .The request is with invalid  value for " +
                        "(requested_expiry).");
            }
            throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "Invalid value for (requested_expiry).");
        }
    }

    /**
     * Checks whether the transaction_context values exists and is valid.
     *
     * @param claimsSet JWT claimsets of the authentication request.
     * @throws CibaAuthFailureException CIBA Authentication Failed Server Exception.
     */
    private void valiateTransactionContext(JWTClaimsSet claimsSet) throws CibaAuthFailureException {

        try {
            // Validation for transaction_context.
            if ((claimsSet.getClaim(CibaConstants.TRANSACTION_CONTEXT)) == null) {
                // Request has no transaction_context claim.
                return;
            }
            if (StringUtils.isBlank(claimsSet.getJSONObjectClaim(CibaConstants.TRANSACTION_CONTEXT).toJSONString())) {
                if (log.isDebugEnabled()) {
                    log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                            claimsSet.getIssuer() + ".The request is with invalid  " +
                            "value for (transaction_context).");
                }
                throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST,
                        "Invalid value for (transaction_context).");
            }
        } catch (ParseException e) {
            throw new CibaAuthFailureException(OAuth2ErrorCodes.SERVER_ERROR, "Error in validating request parameters.",
                    e);
        }
    }

    /**
     * Checks whether the binding_message values exists and is valid.
     *
     * @param claimsSet JWT claimsets of the authentication request.
     * @throws CibaAuthFailureException CIBA Authentication Failed Server Exception.
     */
    private void validateBindingMessage(JWTClaimsSet claimsSet) throws CibaAuthFailureException {

        try {
            // Validation for binding_message.
            if ((claimsSet.getClaim(CibaConstants.BINDING_MESSAGE)) == null) {
                // Request has claim for binding_message.
                return;
            }

            if (StringUtils.isBlank(claimsSet.getStringClaim(CibaConstants.BINDING_MESSAGE))) {
                // Binding_message with a blank value which is not acceptable.
                if (log.isDebugEnabled()) {
                    log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                            claimsSet.getIssuer() +
                            ".The request is with invalid  value for (binding_message).");
                }
                throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST,
                        "Invalid value for (binding_message).");
            }
        } catch (ParseException e) {
            throw new CibaAuthFailureException(OAuth2ErrorCodes.SERVER_ERROR, "Error in validating request parameters.",
                    e);
        }
    }

    /**
     * Checks whether the ACR values exists and is valid.
     *
     * @param claimsSet JWT claimsets of the authentication request.
     * @throws CibaAuthFailureException CIBA Authentication Failed Server Exception.
     */
    private void validateACR(JWTClaimsSet claimsSet) throws CibaAuthFailureException {

        try {
            // Validation for acr values.
            if ((claimsSet.getClaim(Constants.ACR_VALUES)) == null) {
                return;
            }

            if (StringUtils.isBlank(claimsSet.getStringClaim(Constants.ACR_VALUES))) {
                // ACR claim with blank values.
                if (log.isDebugEnabled()) {
                    log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                            claimsSet.getIssuer() + ". The request is with invalid  value for (acr).");
                }
                throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST, "Invalid values for (acr).");
            }
        } catch (ParseException e) {
            throw new CibaAuthFailureException(OAuth2ErrorCodes.SERVER_ERROR, "Error in validating request parameters.",
                    e);
        }
    }

    /**
     * Checks whether the scope exists and is valid.
     *
     * @param claimsSet CIBA Authentication request as JWT claim sets.
     * @throws CibaAuthFailureException CIBA Authentication Failed Exception.
     */
    private void validateScopes(JWTClaimsSet claimsSet) throws CibaAuthFailureException {

        try {
            // Validation for scope.Mandatory parameter for CIBA AuthenticationRequest.
            if (claimsSet.getClaim(Constants.SCOPE) == null) {
                // Missing 'scope' claim in the request.
                if (log.isDebugEnabled()) {
                    log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                            claimsSet.getIssuer() + ".The request is missing the mandatory claim (scope).");
                }
                throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST, "missing parameter (scope).");
            }
            if (StringUtils.isBlank(claimsSet.getStringClaim(Constants.SCOPE))) {
                // Scope is with blank value.
                if (log.isDebugEnabled()) {
                    log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                            claimsSet.getIssuer() + ".The request is with invalid  value for (scope).");
                }
                throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST, "Invalid values for (scope).");
            }
        } catch (ParseException e) {
            throw new CibaAuthFailureException(OAuth2ErrorCodes.SERVER_ERROR, "Error in validating request parameters.",
                    e);
        }
    }

    /**
     * Checks whether the JWT-NBF is valid.
     *
     * @param claimsSet CIBA Authentication request as claim sets..
     * @throws CibaAuthFailureException CIBA Authentication Failed Exception.
     */
    private void validateNBF(JWTClaimsSet claimsSet, long currentTime, long skewTime) throws CibaAuthFailureException {

        // Validation for nbf-time before signed request is acceptable. Mandatory parameter if signed.
        if (claimsSet.getNotBeforeTime() == null) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        claimsSet.getIssuer() + ".The request is missing the mandatory parameter (nbf).");
            }
            throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST, "Missing parameter (nbf).");
        }
        long nbfTime = claimsSet.getNotBeforeTime().getTime();
        if (checkNotBeforeTime(currentTime, nbfTime, skewTime)) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        claimsSet.getIssuer() + ".The request is with invalid  value for (nbf).");
            }
            throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST, "Cannot use this JWT.Failed (nbf).");
        }
    }

    /**
     * Checks whether the JWT-Issued time is valid.
     *
     * @param currentTime Current system time.
     * @param claimsSet   CIBA Authentication request as claim sets.
     * @throws CibaAuthFailureException CIBA Authentication Failed Exception.
     */
    private void validateIssuedTime(JWTClaimsSet claimsSet, long currentTime) throws CibaAuthFailureException {

        // Validation for (iat).Mandatory parameter if signed.
        if (claimsSet.getIssueTime() == null) {
            // (iat) is a null value.
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        claimsSet.getIssuer() + ".The request is missing the mandatory parameter (iat).");
            }
            throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST, "Missing parameter (iat).");
        }

        long issuedTime = claimsSet.getIssueTime().getTime();
        if (issuedTime > currentTime) {
            // Invalid issued time.Issued time is in future.
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        claimsSet.getIssuer() + ".The request is with invalid value for (iat) .");
            }
            throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST, "Invalid value for (iat).");
        }
    }

    /**
     * Checks whether the JWT-Expiry time is valid.
     *
     * @param claimsSet   CIBA Authentication request as claim sets.
     * @param currentTime CurrentTime in milliseconds.
     * @param skewTime    skewtime in milliseconds.
     * @throws CibaAuthFailureException CIBA Authentication Failed Exception.
     */
    private void validateExpiryTime(JWTClaimsSet claimsSet, long currentTime, long skewTime)
            throws CibaAuthFailureException {

        // Validation for expiryTime.
        if (claimsSet.getExpirationTime() == null) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        claimsSet.getIssuer() + ".The request is missing the mandatory parameter (exp).");
            }
            throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST, "Missing parameter (exp).");
        }
        long expiryTime = claimsSet.getExpirationTime().getTime();
        if (expiryTime < currentTime + skewTime) {
            // Invalid token as expired time has passed.
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        claimsSet.getIssuer() + ".The provided JWT is expired.");
            }
            throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST, "JWT expired.");
        }
    }

    /**
     * Checks whether the JWT-ID is valid.
     *
     * @param claimsSet CIBA Authentication request as claim sets.
     * @throws CibaAuthFailureException CIBA Authentication Failed Exception.
     */
    private void validateJti(JWTClaimsSet claimsSet) throws CibaAuthFailureException {

        // Validation for (jti).Mandatory parameter if signed.
        if (StringUtils.isBlank(claimsSet.getJWTID())) {
            // (jti) is a blank value.
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        claimsSet.getIssuer() + ".The request has invalid values for the parameter (jti).");
            }
            throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "Invalid value for the parameter (jti)");
        }
    }

    /**
     * Checks whether the request is properly signed.
     *
     * @param signedJWT SignedJWT.
     * @return Boolean.
     * @throws CibaAuthFailureException CIBA Authentication Failed Exception.
     */
    private Boolean isValidSignature(SignedJWT signedJWT) throws CibaAuthFailureException {

        String alg = signedJWT.getHeader().getAlgorithm().getName();
        if (StringUtils.isEmpty(alg)) {
            throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST, "Algorithm must not be null.");
        }

        if (alg.startsWith("RS")) {
            throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "Provided algorithm: " + alg + " not supported.");
        }
        return true;
    }

    /**
     * Checks whether the audience is valid as expected.
     *
     * @param claimsSet CIBA Authentication request as claim sets.
     * @throws CibaAuthFailureException CIBA Authentication Failed Exception.
     */
    private void validateAudience(JWTClaimsSet claimsSet) throws CibaAuthFailureException {

        List<String> aud = claimsSet.getAudience();
        String clientId = claimsSet.getIssuer();

        try {
            // Validation for aud-audience.
            if (aud.isEmpty()) {
                // No value for audience found in the request.
                if (log.isDebugEnabled()) {
                    log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                            claimsSet.getIssuer() + ".The request is missing the mandatory parameter 'aud'.");
                }
                throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST, " Missing (aud) parameter.");
            }

            OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientId);
            String domain = OAuth2Util.getTenantDomainOfOauthApp(appDO);

            // Getting expected audience dynamically from configs.
            String expectedAudience = OAuth2Util.getIdTokenIssuer(domain);

            // Validation for aud-audience to meet mandated value.
            if (!aud.contains(expectedAudience)) {
                // The audience value does not suit mandated value.
                if (log.isDebugEnabled()) {
                    log.debug("Invalid CIBA Authentication Request made by client with clientID: " + clientId +
                            ". Expected audience: " + expectedAudience + ".");
                }
                throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST,
                        "Parameter (aud) does not meet the expected value: " + expectedAudience + ".");
            }
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            throw new CibaAuthFailureException(OAuth2ErrorCodes.SERVER_ERROR, "Error in validating for (aud).", e);
        }
    }

    /**
     * Checks whether the client is valid.
     *
     * @param request CIBA Authentication request.
     * @throws CibaAuthFailureException CIBA Authentication Failed Exception.
     */
    public void validateClient(String request) throws CibaAuthFailureException {

        try {
            SignedJWT signedJWT = SignedJWT.parse(request);
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            String clientId = claimsSet.getIssuer();

            // Validate whether the claim for the issuer is valid.
            if (StringUtils.isBlank(claimsSet.getIssuer())) {
                // (iss) is a blank value.

                if (log.isDebugEnabled()) {
                    log.debug("Missing issuer of the JWT of the request : " + request);
                }
                throw new CibaAuthFailureException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, "Invalid value for (iss).");
            }

            // Validation for existence of clientApp  in the store.
            OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientId);
            String grantTypes = appDO.getGrantTypes();
            if (StringUtils.isBlank(grantTypes) || !grantTypes.contains(CibaConstants.OAUTH_CIBA_GRANT_TYPE)) {
                if (log.isDebugEnabled()) {
                    log.debug("Client has not configured grant_type: " + CibaConstants.OAUTH_CIBA_GRANT_TYPE);
                }
                throw new CibaAuthFailureException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT,
                        "Client has not configured grant_type properly.");
            }

            if (log.isDebugEnabled()) {
                log.debug("CIBA Authentication Request 'request':" + request +
                        " is having a proper clientID : " + claimsSet.getIssuer() + " as the issuer.");
            }

        } catch (InvalidOAuthClientException e) {
            if (log.isDebugEnabled()) {
                log.debug("The request: " + request + " doesn't have a proper clientID.");
            }
            throw new CibaAuthFailureException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, "Unknown (iss) client.");

        } catch (IdentityOAuth2Exception | ParseException ex) {
            throw new CibaAuthFailureException(OAuth2ErrorCodes.SERVER_ERROR, "Exception in validating for (iss). ");
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
     * Validation for login_hint_token,id_token_hint.
     * Anyone and exactly one is mandatory.
     *
     * @param authRequest CIBA Authentication request.
     * @throws CibaAuthFailureException CIBA Authentication Failed Exception.
     */
    public void validateUserHint(String authRequest) throws CibaAuthFailureException {

        try {
            SignedJWT signedJWT = SignedJWT.parse(authRequest);
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

            // Validation to  check if any hints present.
            if ((claimsSet.getClaim(CibaConstants.LOGIN_HINT_TOKEN) == null)
                    && (claimsSet.getClaim(Constants.LOGIN_HINT) == null)
                    && (claimsSet.getClaim(Constants.ID_TOKEN_HINT) == null)) {

                // All hints are null.
                if (log.isDebugEnabled()) {
                    log.debug("Invalid request. Missing mandatory parameter, 'hints' from the request : "
                            + authRequest);
                }
                throw new CibaAuthFailureException(ErrorCodes.UNAUTHORIZED_USER, "Missing user hints.");
            }

            // Validation when login_hint_token exists.
            if (!(claimsSet.getClaim(CibaConstants.LOGIN_HINT_TOKEN) == null)
                    && (claimsSet.getClaim(Constants.LOGIN_HINT) == null)
                    && (claimsSet.getClaim(Constants.ID_TOKEN_HINT) == null)) {
                if (log.isDebugEnabled()) {
                    log.debug("No Login_hint_token support for current version of IS.Invalid CIBA Authentication " +
                            "request : " + authRequest);
                }
                throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST,
                        "Invalid parameter (login_hint_token)");
            }

            // Validation when login_hint exists.
            if ((claimsSet.getClaim(CibaConstants.LOGIN_HINT_TOKEN) == null)
                    && (!(claimsSet.getClaim(Constants.LOGIN_HINT) == null))
                    && (claimsSet.getClaim(Constants.ID_TOKEN_HINT) == null)) {

                // Claim exists for login_hint.
                if (StringUtils.isBlank(claimsSet.getClaim(Constants.LOGIN_HINT).toString())) {
                    // Login_hint is blank.
                    throw new CibaAuthFailureException(ErrorCodes.UNAUTHORIZED_USER, "login_hint is blank.");
                }
                if (log.isDebugEnabled()) {
                    log.debug("CIBA Authentication Request made by Client with clientID," +
                            claimsSet.getIssuer() + " is having a proper user hint  : " +
                            claimsSet.getClaim(Constants.LOGIN_HINT) + ".");
                }
                return;
            }

            // Validation when id_token_hint exists.
            if ((claimsSet.getClaim(CibaConstants.LOGIN_HINT_TOKEN) == null)
                    && (claimsSet.getClaim(Constants.LOGIN_HINT) == null)
                    && (!(claimsSet.getClaim(Constants.ID_TOKEN_HINT) == null))) {

                // Value exists for id_token_hint
                if (StringUtils.isBlank(claimsSet.getClaim(Constants.ID_TOKEN_HINT).toString())) {
                    // Existing values for id_token_hint are blank.
                    if (log.isDebugEnabled()) {
                        log.debug("Unknown user identity from the request " + authRequest);
                    }
                    throw new CibaAuthFailureException(ErrorCodes.UNAUTHORIZED_USER,
                            "Invalid (sub) value for the provided id_token_hint");
                }

                if (!OAuth2Util.validateIdToken(String.valueOf(claimsSet.getClaim(Constants.ID_TOKEN_HINT)))) {
                    // Provided id_token_hint is not valid.
                    if (log.isDebugEnabled()) {
                        log.debug("Invalid id_token_hint from the request " + authRequest);
                    }
                    throw new CibaAuthFailureException(ErrorCodes.UNAUTHORIZED_USER, "invalid id_token_hint.");
                }

                if (log.isDebugEnabled()) {
                    log.debug("CIBA Authentication Request made by Client with clientID," +
                            claimsSet.getAudience() + " is having a proper id_token_hint: " +
                            claimsSet.getClaim(Constants.ID_TOKEN_HINT) + ".");
                }
            }
        } catch (ParseException ex) {
            throw new CibaAuthFailureException(OAuth2ErrorCodes.SERVER_ERROR,
                    "Error occurred in validating user hints.");
        }
    }

    /**
     * Obtain sub from given id token.
     *
     * @param idTokenHint it carries user identity
     * @return String- the user identity
     * @throws CibaAuthFailureException CIBA Authentication Failed Exception.
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
            throw new CibaAuthFailureException(OAuth2ErrorCodes.SERVER_ERROR, "Error in obtaining (sub) from id_token.",
                    e);
        }
    }

    /**
     * Validate whether Request JWT is in proper formatting.
     *
     * @param authRequest CIBA Authentication Request as a String.
     * @throws CibaAuthFailureException CIBA Authentication Failed Exception.
     */
    public void validateRequest(String authRequest) throws CibaAuthFailureException {

        try {
            // The assertion is not an encrypted one.
            SignedJWT signedJWT = SignedJWT.parse(authRequest);
            Payload payload = signedJWT.getPayload();
            Base64URL signature = signedJWT.getSignature();
            JWSHeader header = signedJWT.getHeader();

            if (payload == null || header == null || signature == null) {
                throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST,
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
                throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST, "invalid parameter (request)");
            }
        } catch (ParseException e) {
            String errorMessage =
                    "Unexpected number of Base64URL parts of the nested JWT payload. Expected number" +
                            " of parts must be three. ";
            throw new CibaAuthFailureException(OAuth2ErrorCodes.INVALID_REQUEST, errorMessage, e);
        }
    }

    /**
     * Extracts validated parameters from request and prepare a DTO.
     *
     * @param request CIBA Authentication Request as a String.
     * @throws CibaAuthFailureException CIBA Authentication Failed Exception.
     */
    public CibaAuthCodeRequest prepareAuthCodeRequest(String request) throws CibaAuthFailureException {

        CibaAuthCodeRequest cibaAuthCodeRequest = new CibaAuthCodeRequest();
        try {

            SignedJWT signedJWT = SignedJWT.parse(request);

            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

            // Set the clientID since properly validated.
            cibaAuthCodeRequest.setIssuer(claimsSet.getIssuer());

            List<String> aud = claimsSet.getAudience();
            // Adding issuer of the request to AuthenticationRequest after validation.
            cibaAuthCodeRequest.setAudience(aud.toArray(new String[aud.size()]));

            // Adding user_hint to the CIBA authentication request after successful validation.
            if (claimsSet.getClaim(Constants.LOGIN_HINT) != null) {
                // Since we have multiple parameters for user hints we need this check.
                cibaAuthCodeRequest.setUserHint(String.valueOf(claimsSet.getClaim(Constants.LOGIN_HINT)));
            } else {
                if (claimsSet.getClaim(Constants.ID_TOKEN_HINT) != null) {
                    cibaAuthCodeRequest.setUserHint(
                            getUserfromIDToken(String.valueOf(claimsSet.getClaim(Constants.ID_TOKEN_HINT))));
                }
            }

            // Set the validated value to JWT.
            cibaAuthCodeRequest.setJwtId(claimsSet.getJWTID());

            // Setting the validated expiredTime of the AuthenticationRequest.
            cibaAuthCodeRequest.setExpiredTime(claimsSet.getExpirationTime().getTime());

            // Setting the validated IssuedTime.
            cibaAuthCodeRequest.setIssuedTime(claimsSet.getIssueTime().getTime());

            // Setting the validated NBF after validation of the AuthenticationRequest.
            cibaAuthCodeRequest.setNotBeforeTime(claimsSet.getNotBeforeTime().getTime());

            // Setting the scope of the AuthenticationRequest.
            cibaAuthCodeRequest.setScopes(OAuth2Util.buildScopeArray(claimsSet.getStringClaim(Constants.SCOPE)));

            // Setting scope to CIBA AuthenticationRequest after validation.
            cibaAuthCodeRequest.setAcrValues(buildACRArray(claimsSet.getStringClaim(Constants.ACR_VALUES)));

            // Setting binding_message to AuthenticationRequest after successful validation.
            cibaAuthCodeRequest.setBindingMessage(claimsSet.getStringClaim(CibaConstants.BINDING_MESSAGE));

            // Setting transaction_context to AuthenticationRequest after successful validation.
            cibaAuthCodeRequest.setTransactionContext(
                    (claimsSet.getJSONObjectClaim(CibaConstants.TRANSACTION_CONTEXT).toJSONString()));

            // Setting requested_expiry to AuthenticationRequest after successful validation.
            if (claimsSet.getClaim(CibaConstants.REQUESTED_EXPIRY) != null) {
                cibaAuthCodeRequest.setRequestedExpiry(claimsSet.getLongClaim(CibaConstants.REQUESTED_EXPIRY));
            } else {
                cibaAuthCodeRequest.setRequestedExpiry(0);
            }
        } catch (ParseException e) {
            throw new CibaAuthFailureException(OAuth2ErrorCodes.SERVER_ERROR,
                    "Error when processing request parameters.", e);
        }
        return cibaAuthCodeRequest;
    }

    /**
     * Build and return ACR string as array.
     *
     * @param acrString ACR values as a String.
     * @return String Array.
     */
    public static String[] buildACRArray(String acrString) {

        if (StringUtils.isNotBlank(acrString)) {
            acrString = acrString.trim();
            return acrString.split("\\s");
        }
        return new String[0];
    }
}
