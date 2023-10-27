/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.jwt.JWKSBasedJWTValidator;
import org.wso2.carbon.identity.openidconnect.model.Constants;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;

import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;

import static org.wso2.carbon.identity.openidconnect.model.Constants.PS;
import static org.wso2.carbon.identity.openidconnect.model.Constants.RS;

/**
 * Util class for request object validator
 */
public class RequestObjectValidatorUtil {

    private static final Log log = LogFactory.getLog(RequestObjectValidatorUtil.class);
    private static final String FAPI_SIGNATURE_ALG_CONFIGURATION = "OAuth.OpenIDConnect.FAPI." +
            "AllowedSignatureAlgorithms.AllowedSignatureAlgorithm";

    /**
     * Validate the signature of the request object
     * @param requestObject Request Object
     * @param oAuth2Parameters OAuth2 Parameters
     * @return is signature valid
     * @throws RequestObjectException
     */
    public static boolean validateSignature(RequestObject requestObject, OAuth2Parameters oAuth2Parameters) throws
            RequestObjectException {

        boolean isVerified;
        Certificate certificate = null;
        SignedJWT jwt = requestObject.getSignedJWT();
        OAuthAppDO oAuthAppDO = null;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(oAuth2Parameters.getClientId(),
                    oAuth2Parameters.getTenantDomain());
            String algorithm = oAuthAppDO.getRequestObjectSignatureAlgorithm();
            if (StringUtils.isNotEmpty(algorithm) && !algorithm.equals(jwt.getHeader().getAlgorithm().getName())) {
                throw new RequestObjectException("Request Object signature verification failed. Invalid signature " +
                        "algorithm.", OAuth2ErrorCodes.INVALID_REQUEST);
            }
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            throw new RequestObjectException(OAuth2ErrorCodes.SERVER_ERROR, "Error while retrieving Oauth application "
                    + "to check signature algorithm.", e);
        }
        try {
            certificate =
                    getCertificateForAlias(oAuth2Parameters.getTenantDomain(), oAuth2Parameters.getClientId());
        } catch (RequestObjectException e) {
            String message = "Error retrieving public certificate for service provider, checking whether a jwks " +
                    "endpoint is configured for the service provider with client_id: " + oAuth2Parameters.getClientId();
            log.warn(message);
            if (log.isDebugEnabled()) {

                log.debug(message, e);
            }
        }
        String alg = jwt.getHeader().getAlgorithm().getName();
        String clientId = oAuth2Parameters.getClientId();

        if (!isValidSignatureAlgorithm(clientId, alg)) {
            throw new RequestObjectException("Request Object signature verification failed. Invalid signature " +
                    "algorithm.", OAuth2ErrorCodes.INVALID_REQUEST);
        }
        if (isFapiConformant(clientId) && !isValidFAPISignatureAlgorithm(clientId, alg)) {
            throw new RequestObjectException("Request Object signature verification failed. Invalid signature " +
                    "algorithm.", OAuth2ErrorCodes.INVALID_REQUEST);
        }
        if (certificate == null) {
            if (log.isDebugEnabled()) {

                log.debug("Public certificate not configured for Service Provider with " +
                        "client_id: " + clientId + " of tenantDomain: " + oAuth2Parameters
                        .getTenantDomain() + ". Fetching the jwks endpoint for validating request object");
            }
            String jwksUri = getSpProperty(clientId, Constants.JWKS_URI);
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
     * Get service provider property.
     *
     * @param clientId     client id
     * @param propertyName property name
     * @return property value
     * @throws RequestObjectException if error occurred while getting the service provider
     */
    private static String getSpProperty(String clientId, String propertyName) throws RequestObjectException {

        String propertyValue = StringUtils.EMPTY;
        ServiceProviderProperty[] spProperties;
        try {
            spProperties = OAuth2Util.getServiceProvider(clientId).getSpProperties();
        } catch (IdentityOAuth2Exception e) {
            throw new RequestObjectException("Error while getting the service provider for client ID " + clientId,
                    OAuth2ErrorCodes.SERVER_ERROR, e);
        }

        if (spProperties != null) {
            for (ServiceProviderProperty spProperty : spProperties) {
                if (propertyName.equals(spProperty.getName())) {
                    propertyValue = spProperty.getValue();
                    if (log.isDebugEnabled()) {
                        log.debug("Found " + propertyName + propertyValue + " for service provider with client id " +
                                clientId);
                    }
                    break;
                }
            }
        } else {
            return StringUtils.EMPTY;
        }
        return propertyValue;
    }

    /**
     * Validating signature based on jwks endpoint.
     *
     * @param signedJWT signed JWT
     * @param jwksUri   Uri of the JWKS endpoint
     * @return signature validity
     * @throws RequestObjectException
     */
    public static boolean isSignatureVerified(SignedJWT signedJWT, String jwksUri) throws RequestObjectException {

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
        } else {
            log.warn("JWKS URI is empty");
        }
        return false;

    }

    /**
     * Validate the signature algorithm according to FAPI specification.
     * According to FAPI, signature algorithm should be PS256 or ES256.
     * <a href="https://openid.net/specs/openid-financial-api-part-2-1_0.html#algorithm-considerations">...</a>
     *
     * @param clientId  client id
     * @param algorithm signature algorithm
     * @return is valid signature algorithm
     */
    private static boolean isValidFAPISignatureAlgorithm(String clientId, String algorithm) {

        List<String> allowedFAPIAlgorithms = IdentityUtil.getPropertyAsList(FAPI_SIGNATURE_ALG_CONFIGURATION);

        if (!allowedFAPIAlgorithms.contains(algorithm)) {
            log.debug("Invalid signature algorithm. Signature algorithm should be one of " +
                    String.join(", ", allowedFAPIAlgorithms));
            return false;
        }
        return true;
    }

    /**
     * Validate the signature algorithm against the registered signature algorithms if exists.
     *
     * @param clientId  client id
     * @param algorithm signature algorithm
     * @return is valid signature algorithm
     * @throws RequestObjectException if an error occurred while getting the service provider
     */
    private static boolean isValidSignatureAlgorithm(String clientId, String algorithm) throws RequestObjectException {

        String requestObjSignatureAlgorithms = getSpProperty(clientId, Constants.REQUEST_OBJECT_SIGNING_ALG);
        if (StringUtils.isNotEmpty(requestObjSignatureAlgorithms)) {
            List<String> allowedAlgorithms = Arrays.asList(requestObjSignatureAlgorithms.split(" "));
            if (!allowedAlgorithms.contains(algorithm)) {
                log.debug("Invalid signature algorithm. Signature algorithm should be one of registered algorithms " +
                        String.join(", ", allowedAlgorithms));
                return false;
            }
        }
        return true;
    }

    /**
     * Get certificate for the given alias
     * @param tenantDomain Tenant Domain
     * @param alias Alias
     * @return Certificate for the given Alias
     * @throws RequestObjectException
     */
    protected static Certificate getCertificateForAlias(String tenantDomain, String alias) throws
            RequestObjectException {

        return getX509CertOfOAuthApp(alias, tenantDomain);
    }

    /**
     * Get the X509Certificate object containing the public key of the OAuth client.
     *
     * @param clientId clientID of the OAuth client (Service Provider).
     * @param tenantDomain tenant domain of Service Provider.
     * @return X509Certificate object containing the public certificate of the Service Provider.
     */
    public static Certificate getX509CertOfOAuthApp(String clientId, String tenantDomain) throws
            RequestObjectException {

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
     * @param signedJWT       signed JWT
     * @param x509Certificate X509 certificate
     * @return signature validity
     */
    public static boolean isSignatureVerified(SignedJWT signedJWT, Certificate x509Certificate) {

        JWSVerifier verifier;
        JWSHeader header = signedJWT.getHeader();
        if (x509Certificate == null) {
            if (log.isDebugEnabled()) {
                log.debug("Unable to locate certificate for JWT " + header.toString());
            }
            return false;
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
                if (log.isDebugEnabled()) {
                    log.debug("Public key is not an RSA public key.");
                }
                return false;
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Signature Algorithm not supported yet : " + alg);
            }
            return false;
        }
        // At this point 'verifier' will never be null;
        try {
            return signedJWT.verify(verifier);
        } catch (JOSEException e) {
            if (log.isDebugEnabled()) {
                log.debug("Unable to verify the signature of the request object: " + signedJWT.serialize(), e);
            }
            return false;
        }
    }

    private static boolean isFapiConformant(String clientId) throws RequestObjectException {

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
