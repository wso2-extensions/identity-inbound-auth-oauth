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
package org.wso2.carbon.identity.openidconnect;

import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.RequestObjectValidatorUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.model.Constants;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.utils.DiagnosticLog;

import java.security.cert.Certificate;
import java.util.Date;
import java.util.List;
import java.util.regex.Pattern;

import static org.apache.commons.lang.StringUtils.isEmpty;
import static org.apache.commons.lang.StringUtils.isNotEmpty;

/**
 * This class validates request object parameter value which comes with the OIDC authorization request as an optional
 * parameter
 */

public class RequestObjectValidatorImpl implements RequestObjectValidator {

    private static final String OIDC_IDP_ENTITY_ID = "IdPEntityId";
    private static final String OIDC_ID_TOKEN_ISSUER_ID = "OAuth.OpenIDConnect.IDTokenIssuerID";
    private static final int MILLISECONDS_PER_SECOND = 1000;
    private static final int MILLISECONDS_PER_HOUR = 3600000;
    private static Log log = LogFactory.getLog(RequestObjectValidatorImpl.class);

    @Override
    public boolean isSigned(RequestObject requestObject) {

        return requestObject.getSignedJWT() != null;
    }

    @Override
    public boolean validateSignature(RequestObject requestObject, OAuth2Parameters oAuth2Parameters) throws
            RequestObjectException {

        return RequestObjectValidatorUtil.validateSignature(requestObject, oAuth2Parameters);
    }

    /**
     * @deprecated use @{@link RequestObjectValidatorUtil#isSignatureVerified(SignedJWT, String)}} instead
     * to verify the signature
     * Validating signature based on jwks endpoint.
     *
     * @param signedJWT signed JWT
     * @param jwksUri   Uri of the JWKS endpoint
     * @throws RequestObjectException
     */
    @Deprecated
    protected boolean isSignatureVerified(SignedJWT signedJWT, String jwksUri) throws RequestObjectException {

        return RequestObjectValidatorUtil.isSignatureVerified(signedJWT, jwksUri);

    }

    /**
     * Decide whether this request object is a signed object encrypted object or a nested object.
     *
     * @param requestObject    request object
     * @param oAuth2Parameters oAuth2Parameters
     * @throws RequestObjectException
     */
    @Override
    public boolean validateRequestObject(RequestObject requestObject, OAuth2Parameters oAuth2Parameters)
            throws RequestObjectException {

        if (!validateClientIdAndResponseType(requestObject, oAuth2Parameters)) {
            return false;
        }

        if (!checkExpirationTime(requestObject)) {
            return false;
        }

        if (!isValidRedirectUri(requestObject, oAuth2Parameters)) {
            return false;
        }

        if (isParamPresent(requestObject, Constants.REQUEST_URI) || isParamPresent(requestObject, Constants.REQUEST)) {
            return false;
        }

        if (requestObject.isSigned()) {
            if (!isValidIssuer(requestObject, oAuth2Parameters)) {
                return false;
            }

            if (!isValidAudience(requestObject, oAuth2Parameters)) {
                return false;
            }
        }

        if (isFapiConformant(oAuth2Parameters.getClientId())) {
            checkFapiMandatedParams(requestObject);
            if (!isValidNbfExp(requestObject)) {
                return false;
            }
        }

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.VALIDATE_REQUEST_OBJECT)
                    .resultMessage("Request object validation is successful.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS));
        }
        return true;
    }

    private void checkFapiMandatedParams(RequestObject requestObject) throws RequestObjectException {

        String[] mandatoryParams = {Constants.SCOPE, Constants.NONCE, Constants.REDIRECT_URI};
        for (String param : mandatoryParams) {
            if (!isParamPresent(requestObject, param)) {
                throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST,
                        param + " is not present in the request object.");
            }
        }
    }

    protected boolean isValidAudience(RequestObject requestObject, OAuth2Parameters oAuth2Parameters) throws
            RequestObjectException {

        String tokenEPUrl = getTokenEpURL(oAuth2Parameters.getTenantDomain());
        List<String> audience = requestObject.getClaimsSet().getAudience();
        return validateAudience(tokenEPUrl, audience);
    }

    private boolean checkExpirationTime(RequestObject requestObject) throws RequestObjectException {

        Date expirationTime = requestObject.getClaimsSet().getExpirationTime();
        if (expirationTime != null) {
            long timeStampSkewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
            long expirationTimeInMillis = expirationTime.getTime();
            long currentTimeInMillis = System.currentTimeMillis();
            if ((currentTimeInMillis + timeStampSkewMillis) > expirationTimeInMillis) {
                String msg = "Request Object is expired." +
                        ", Expiration Time(ms) : " + expirationTimeInMillis +
                        ", TimeStamp Skew : " + timeStampSkewMillis +
                        ", Current Time : " + currentTimeInMillis + ". Token Rejected.";
                logAndReturnFalse(msg);
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                            OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                            OAuthConstants.LogConstants.ActionIDs.VALIDATE_REQUEST_OBJECT)
                            .inputParam("request object expiration time (ms)", expirationTime)
                            .resultMessage("Request Object is Expired.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED));
                }
                throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, "Request Object " +
                        "is Expired.");
            }
        }
        return true;
    }

    /**
     * Validate the request object nbf claim and exp claim according to the FAPI specification.
     * <a href="https://openid.net/specs/openid-financial-api-part-2-1_0.html#authorization-server">...</a>
     *
     * @param requestObject request object
     * @return true if both claims are valid
     * @throws RequestObjectException if nbf exp validation fails
     */
    protected boolean isValidNbfExp(RequestObject requestObject) throws RequestObjectException {

        Date nbfTime = requestObject.getClaimsSet().getNotBeforeTime();
        Date expirationTime = requestObject.getClaimsSet().getExpirationTime();

        String errorMsg = null;
        String errorLog = null;
        if (nbfTime == null) {
            errorMsg = "Request Object does not contain Not Before Time.";
        } else if (expirationTime == null) {
            errorMsg = "Request Object does not contain Expiration Time.";
        } else {
            long timeStampSkewMillis = OAuthServerConfiguration.getInstance()
                    .getTimeStampSkewInSeconds() * MILLISECONDS_PER_SECOND;
            long nbfTimeInMillis = nbfTime.getTime();
            long expirationTimeInMillis = expirationTime.getTime();
            long currentTimeInMillis = System.currentTimeMillis();
            // nbf should be older than current time.
            if ((currentTimeInMillis + timeStampSkewMillis) < nbfTimeInMillis) {
                errorMsg = "Request Object is not valid yet.";
                errorLog = String.format("Request Object is not valid yet." +
                        ", Not Before Time(ms) : %d, TimeStamp Skew : %d, Current Time : %d" + ". Token Rejected.",
                        nbfTimeInMillis, timeStampSkewMillis, currentTimeInMillis);
            } else if ((currentTimeInMillis + timeStampSkewMillis) - MILLISECONDS_PER_HOUR > nbfTimeInMillis) {
                // nbf should not be older than 1 hour from current time
                errorMsg = "Request Object nbf claim is too old.";
                errorLog = String.format("Request Object nbf claim is too old." +
                        ", Not Before Time(ms) : %d, TimeStamp Skew : %d, Current Time : %d" + ". Token Rejected.",
                        nbfTimeInMillis, timeStampSkewMillis, currentTimeInMillis);
            } else if (expirationTimeInMillis > nbfTimeInMillis + MILLISECONDS_PER_HOUR) {
                // exp time should not be older than 1 hour from nbf time
                errorMsg = "Request Object expiry time is too far in the future than not before time.";
                errorLog = String.format("Request Object expiry time is too far in the future than not before time." +
                        ", Expiration Time(ms) : %d, Not Before Time(ms) : %d, Current Time : %d" + ". Token Rejected.",
                        expirationTimeInMillis, nbfTimeInMillis, currentTimeInMillis);
            }
        }

        if (StringUtils.isNotBlank(errorMsg)) {
            errorLog = StringUtils.isEmpty(errorLog) ? errorMsg : errorLog;
            logAndReturnFalse(errorLog);
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.VALIDATE_REQUEST_OBJECT)
                        .resultMessage(errorLog)
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED));
            }
            throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, errorMsg);
        }
        return true;
    }

    protected boolean validateClientIdAndResponseType(RequestObject requestObject, OAuth2Parameters oauthRequest)
            throws RequestObjectException {

        String clientIdInReqObj = requestObject.getClaimValue(Constants.CLIENT_ID);
        String responseTypeInReqObj = requestObject.getClaimValue(Constants.RESPONSE_TYPE);
        final String errorMsg = "Request Object and Authorization request contains unmatched ";

        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.VALIDATE_REQUEST_OBJECT)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.FAILED);
        }
        if (!isValidParameter(oauthRequest.getClientId(), clientIdInReqObj)) {
            if (diagnosticLogBuilder != null) {
                // diagnosticLogBuilder will be null if diagnostic logs are disabled.
                diagnosticLogBuilder.inputParam("client id in request", oauthRequest.getClientId())
                        .inputParam("client id in request object", clientIdInReqObj)
                        .resultMessage(errorMsg + Constants.CLIENT_ID);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, errorMsg + Constants
                    .CLIENT_ID);
        }

        if (!isValidParameter(oauthRequest.getResponseType(), responseTypeInReqObj)) {
            if (diagnosticLogBuilder != null) {
                diagnosticLogBuilder.inputParam("response type in request", oauthRequest.getResponseType())
                        .inputParam("response type in request object", responseTypeInReqObj)
                        .resultMessage(errorMsg + Constants.RESPONSE_TYPE);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST,
                    errorMsg + Constants.RESPONSE_TYPE);
        }
        return true;
    }

    protected boolean isValidParameter(String authParam, String requestObjParam) {

        return StringUtils.isEmpty(requestObjParam) || requestObjParam.equals(authParam);
    }

    /**
     * Return the alias of the resident IDP to validate the audience value of the Request Object.
     *
     * @param tenantDomain
     * @return tokenEndpoint of the Issuer
     * @throws IdentityOAuth2Exception
     */
    protected String getTokenEpURL(String tenantDomain) throws RequestObjectException {

        String residentIdpAlias = StringUtils.EMPTY;
        IdentityProvider residentIdP;
        try {
            residentIdP = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
            FederatedAuthenticatorConfig oidcFedAuthn = IdentityApplicationManagementUtil
                    .getFederatedAuthenticator(residentIdP.getFederatedAuthenticatorConfigs(),
                            IdentityApplicationConstants.Authenticator.OIDC.NAME);

            Property idPEntityIdProperty =
                    IdentityApplicationManagementUtil.getProperty(oidcFedAuthn.getProperties(), OIDC_IDP_ENTITY_ID);
            if (idPEntityIdProperty != null) {
                residentIdpAlias = idPEntityIdProperty.getValue();
                if (log.isDebugEnabled()) {
                    log.debug("Found IdPEntityID: " + residentIdpAlias + " for tenantDomain: " + tenantDomain);
                }
            }
        } catch (IdentityProviderManagementException e) {
            log.error("Error while loading OAuth2TokenEPUrl of the resident IDP of tenant:" + tenantDomain, e);
            throw new RequestObjectException(OAuth2ErrorCodes.SERVER_ERROR, "Server Error while validating audience " +
                    "of Request Object.");
        }

        if (isEmpty(residentIdpAlias)) {
            residentIdpAlias = IdentityUtil.getProperty(OIDC_ID_TOKEN_ISSUER_ID);
            if (isNotEmpty(residentIdpAlias)) {
                if (log.isDebugEnabled()) {
                    log.debug("'IdPEntityID' property was empty for tenantDomain: " + tenantDomain + ". Using " +
                            "OIDC IDToken Issuer value: " + residentIdpAlias + " as alias to identify Resident IDP.");
                }
            }
        }
        return residentIdpAlias;
    }

    protected boolean isValidIssuer(RequestObject requestObject, OAuth2Parameters oAuth2Parameters) {

        String issuer = requestObject.getClaimsSet().getIssuer();
        boolean isValid = StringUtils.isNotEmpty(issuer) && issuer.equals(oAuth2Parameters.getClientId());
        if (!isValid) {
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.VALIDATE_REQUEST_OBJECT)
                        .inputParam("issuer", issuer)
                        .inputParam(LogConstants.InputKeys.CLIENT_ID, oAuth2Parameters.getClientId())
                        .resultMessage("'issuer' field in request object should match with 'client_id' in request.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED));
            }
        }
        return isValid;
    }

    private boolean isParamPresent(RequestObject requestObject, String claim) {

        return StringUtils.isNotEmpty(requestObject.getClaimValue(claim));
    }

    /**
     * Check whether the Token is indented for the server
     *
     * @param currentAudience
     * @param audience
     * @return
     * @throws IdentityOAuth2Exception
     */
    protected boolean validateAudience(String currentAudience, List<String> audience) {

        for (String aud : audience) {
            if (StringUtils.equals(currentAudience, aud)) {
                return true;
            }
        }
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.VALIDATE_REQUEST_OBJECT)
                    .inputParam("audience", audience)
                    .configParam("token endpoint URL", currentAudience)
                    .resultMessage("None of the audiences in request object matched the token endpoint.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.FAILED));
        }
        return logAndReturnFalse("None of the audience values matched the tokenEndpoint Alias: " + currentAudience);
    }

    /**
     * @deprecated use @{@link RequestObjectValidatorImpl#getX509CertOfOAuthApp(String, String)}} instead
     * to retrieve the public certificate of the Service Provider in X509 format.
     */
    @Deprecated
    protected Certificate getCertificateForAlias(String tenantDomain, String alias) throws RequestObjectException {
        return getX509CertOfOAuthApp(alias, tenantDomain);
    }

    /**
     * @deprecated use @{@link RequestObjectValidatorUtil#getX509CertOfOAuthApp(String, String)}} instead
     * to get the X509Certificate object containing the public key of the OAuth client.
     *
     * @param clientId clientID of the OAuth client (Service Provider).
     * @param tenantDomain tenant domain of Service Provider.
     * @return X509Certificate object containing the public certificate of the Service Provider.
     */
    @Deprecated
    protected Certificate getX509CertOfOAuthApp(String clientId, String tenantDomain) throws RequestObjectException {

        return RequestObjectValidatorUtil.getX509CertOfOAuthApp(clientId, tenantDomain);
    }

    /**
     * @deprecated use @{@link RequestObjectValidatorUtil#isSignatureVerified(SignedJWT, Certificate)}} instead
     * to verify the signature
     * Validate the signedJWT signature with given certificate
     *
     * @param signedJWT Signed JWT
     * @param x509Certificate X509 Certificate
     * @return is signature valid
     */
    @Deprecated
    protected boolean isSignatureVerified(SignedJWT signedJWT, Certificate x509Certificate) {

        return RequestObjectValidatorUtil.isSignatureVerified(signedJWT, x509Certificate);
    }

    /**
     * Check if the redirect uri in the request object is valid.
     *
     * @param requestObject    Request object.
     * @param oAuth2Parameters OAuth2 parameters.
     * @return True if redirect uri is valid.
     */
    protected boolean isValidRedirectUri(RequestObject requestObject, OAuth2Parameters oAuth2Parameters) {

        boolean isValid;
        String redirectUriInReqObj = requestObject.getClaimValue(Constants.REDIRECT_URI);
        String redirectURI = oAuth2Parameters.getRedirectURI();

        if (StringUtils.isNotEmpty(redirectURI) && redirectURI.startsWith(OAuthConstants.CALLBACK_URL_REGEXP_PREFIX)) {
            String regex = redirectURI.substring(OAuthConstants.CALLBACK_URL_REGEXP_PREFIX.length());
            isValid = Pattern.matches(regex, redirectUriInReqObj);
        } else {
            isValid = StringUtils.isBlank(redirectUriInReqObj) || StringUtils.equals(redirectUriInReqObj, redirectURI);
        }

        if (!isValid) {
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.VALIDATE_REQUEST_OBJECT)
                        .inputParam("redirect URI in request", oAuth2Parameters.getRedirectURI())
                        .inputParam("redirect URI in request object", redirectUriInReqObj)
                        .resultMessage("Redirect URI in request object does not match with redirect URI in request.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED));
            }
        }
        return isValid;
    }

    /**
     * Message is logged and returns false
     *
     * @param errorMessage
     * @return
     */
    private boolean logAndReturnFalse(String errorMessage) {

        if (log.isDebugEnabled()) {
            log.debug(errorMessage);
        }
        return false;
    }

    private boolean isFapiConformant(String clientId) throws RequestObjectException {

        try {
            return OAuth2Util.isFapiConformantApp(clientId);
        } catch (InvalidOAuthClientException e) {
            throw new RequestObjectException(OAuth2ErrorCodes.INVALID_CLIENT, "Could not find an existing app for " +
                    "clientId: " + clientId, e);
        } catch (IdentityOAuth2Exception e) {
            throw new RequestObjectException(OAuth2ErrorCodes.SERVER_ERROR, "Error while obtaining the service " +
                    "provider for clientId: " + clientId, e);
        }
    }
}
