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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.jwt.JWKSBasedJWTValidator;
import org.wso2.carbon.identity.openidconnect.model.Constants;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.List;
import static org.apache.commons.lang.StringUtils.isEmpty;
import static org.apache.commons.lang.StringUtils.isNotEmpty;
import static org.wso2.carbon.identity.openidconnect.model.Constants.RS;
import static org.wso2.carbon.identity.openidconnect.model.Constants.PS;

/**
 * This class validates request object parameter value which comes with the OIDC authorization request as an optional
 * parameter
 */

public class RequestObjectValidatorImpl implements RequestObjectValidator {

    private static final String OIDC_IDP_ENTITY_ID = "IdPEntityId";
    private static final String OIDC_ID_TOKEN_ISSUER_ID = "OAuth.OpenIDConnect.IDTokenIssuerID";
    private static Log log = LogFactory.getLog(RequestObjectValidatorImpl.class);

    @Override
    public boolean isSigned(RequestObject requestObject) {

        return requestObject.getSignedJWT() != null;
    }

    @Override
    public boolean validateSignature(RequestObject requestObject, OAuth2Parameters oAuth2Parameters) throws
            RequestObjectException {

        boolean isVerified;
        Certificate certificate = null;
        SignedJWT jwt = requestObject.getSignedJWT();
        try {
             certificate =
                    getCertificateForAlias(oAuth2Parameters.getTenantDomain(), oAuth2Parameters.getClientId());
        } catch (RequestObjectException e) {
            String message = "Error retrieving public certificate for service provider checking whether a jwks " +
                    "endpoint is configured for the service provider with client_id: " + oAuth2Parameters.getClientId();
            log.warn(message);
            if (log.isDebugEnabled()) {

                log.debug(message, e);
            }
        }
        if (certificate == null) {
            if (log.isDebugEnabled()) {

                log.debug("Public certificate not configured for Service Provider with " +
                        "client_id: " + oAuth2Parameters.getClientId() + " of tenantDomain: " + oAuth2Parameters
                        .getTenantDomain() + ". Fetching the jwks endpoint for validating request object");
            }
            String jwksUri = getJWKSEndpoint(oAuth2Parameters);
            isVerified = isSignatureVerified(jwt, jwksUri);
        } else {
            if (log.isDebugEnabled()) {

                log.debug("Public certificate configured for Service Provider with " +
                        "client_id: " + oAuth2Parameters.getClientId() + " of tenantDomain: " + oAuth2Parameters
                        .getTenantDomain() + ". Using public certificate  for validating request object");
            }
            isVerified = isSignatureVerified(jwt, certificate);
        }
        requestObject.setIsSignatureValid(isVerified);
        return isVerified;
    }

    /**
     * Fetch JWKS endpoint using OAuth2 Parameters.
     *
     * @param oAuth2Parameters  oAuth2Parameters
     */
    private String getJWKSEndpoint(OAuth2Parameters oAuth2Parameters) throws RequestObjectException {

        String jwksUri = StringUtils.EMPTY;
        ServiceProviderProperty[] spProperties;
        try {
            spProperties = OAuth2Util.getServiceProvider(oAuth2Parameters.getClientId())
                    .getSpProperties();
        } catch (IdentityOAuth2Exception e) {
            throw new RequestObjectException("Error while getting the service provider for client ID " +
                    oAuth2Parameters.getClientId(), OAuth2ErrorCodes.SERVER_ERROR, e);
        }

        if (spProperties != null) {
            for (ServiceProviderProperty spProperty : spProperties) {
                if (Constants.JWKS_URI.equals(spProperty.getName())) {
                    jwksUri = spProperty.getValue();
                    if (log.isDebugEnabled()) {
                        log.debug("Found jwks endpoint " + jwksUri + " for service provider with client id " +
                                oAuth2Parameters.getClientId());
                    }
                    break;
                }
            }
        } else {
            return StringUtils.EMPTY;
        }
        return jwksUri;
    }

    /**
     * Validating signature based on jwks endpoint.
     *
     * @param signedJWT signed JWT
     * @param jwksUri   Uri of the JWKS endpoint
     * @throws RequestObjectException
     */
    protected boolean isSignatureVerified(SignedJWT signedJWT, String jwksUri) throws RequestObjectException {

        // Validate the signature of the assertion using the jwks endpoint.
        if (StringUtils.isNotBlank(jwksUri)) {
            String jwtString = signedJWT.getParsedString();
            String alg = signedJWT.getHeader().getAlgorithm().getName();
            try {
                return new JWKSBasedJWTValidator().validateSignature(jwtString, jwksUri, alg, MapUtils.EMPTY_MAP);
            } catch (IdentityOAuth2Exception e) {
                String errorMessage = "Error occurred while validating request object signature using jwks endpoint";
                throw new RequestObjectException(errorMessage, OAuth2ErrorCodes.SERVER_ERROR, e);
            }
        }
        return false;

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

        boolean isValid = validateClientIdAndResponseType(requestObject, oAuth2Parameters) && checkExpirationTime
                (requestObject);
        if (isParamPresent(requestObject, Constants.REQUEST_URI)) {
            isValid = false;
        } else if (isParamPresent(requestObject, Constants.REQUEST)) {
            isValid = false;
        } else if (requestObject.isSigned()) {
            isValid = isValidIssuer(requestObject, oAuth2Parameters) && isValidAudience(requestObject,
                    oAuth2Parameters);
        }
        return isValid;
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
                throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, "Request Object " +
                        "is Expired.");
            }
        }
        return true;
    }

    protected boolean validateClientIdAndResponseType(RequestObject requestObject, OAuth2Parameters oauthRequest)
            throws RequestObjectException {

        String clientIdInReqObj = requestObject.getClaimValue(Constants.CLIENT_ID);
        String responseTypeInReqObj = requestObject.getClaimValue(Constants.RESPONSE_TYPE);
        final String errorMsg = "Request Object and Authorization request contains unmatched ";

        if (!isValidParameter(oauthRequest.getClientId(), clientIdInReqObj)) {
            throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, errorMsg + Constants
                    .CLIENT_ID);
        }

        if (!isValidParameter(oauthRequest.getResponseType(), responseTypeInReqObj)) {
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
        return StringUtils.isNotEmpty(issuer) && issuer.equals(oAuth2Parameters.getClientId());
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
     * Get the X509Certificate object containing the public key of the OAuth client.
     *
     * @param clientId clientID of the OAuth client (Service Provider).
     * @param tenantDomain tenant domain of Service Provider.
     * @return X509Certificate object containing the public certificate of the Service Provider.
     */
    protected Certificate getX509CertOfOAuthApp(String clientId, String tenantDomain) throws RequestObjectException {


        try {
            return OAuth2Util.getX509CertOfOAuthApp(clientId, tenantDomain);
        } catch (IdentityOAuth2Exception e) {
            String errorMsg = "Error retrieving application certificate of OAuth app with client_id: " + clientId +
                    " , tenantDomain: " + tenantDomain;
            if (StringUtils.isNotBlank(e.getMessage())) {
                // We expect OAuth2Util.getX509CertOfOAuthApp() to throw an exception with a more specific reason for
                // not being able to retrieve the X509 Cert of the service provider.
                errorMsg = e.getMessage();
            }
            throw new RequestObjectException(errorMsg, e);
        }
    }

    /**
     * Validate the signedJWT signature with given certificate
     *
     * @param signedJWT
     * @param x509Certificate
     * @return
     */
    protected boolean isSignatureVerified(SignedJWT signedJWT, Certificate x509Certificate) {

        JWSVerifier verifier;
        JWSHeader header = signedJWT.getHeader();
        if (x509Certificate == null) {
            return logAndReturnFalse("Unable to locate certificate for JWT " + header.toString());
        }

        String alg = signedJWT.getHeader().getAlgorithm().getName();
        if (log.isDebugEnabled()) {
            log.debug("Signature Algorithm found in the JWT Header: " + alg);
        }
        if (alg.indexOf(RS) == 0 || alg.indexOf(PS) == 0) {
            // At this point 'x509Certificate' will never be null.
            PublicKey publicKey = x509Certificate.getPublicKey();
            if (publicKey instanceof RSAPublicKey) {
                verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
            } else {
                return logAndReturnFalse("Public key is not an RSA public key.");
            }
        } else {
            return logAndReturnFalse("Signature Algorithm not supported yet : " + alg);
        }
        // At this point 'verifier' will never be null;
        try {
            return signedJWT.verify(verifier);
        } catch (JOSEException e) {
            return logAndReturnFalse("Unable to verify the signature of the request object: " + signedJWT.serialize());
        }
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

}
