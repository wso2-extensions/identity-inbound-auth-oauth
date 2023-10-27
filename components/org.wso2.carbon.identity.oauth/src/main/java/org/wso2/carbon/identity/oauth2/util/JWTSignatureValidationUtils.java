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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ServerException;
import org.wso2.carbon.identity.oauth2.validators.jwt.JWKSBasedJWTValidator;

import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

/**
 * Utility class for JWT Signature Validation related functionalities.
 */
public class JWTSignatureValidationUtils {

    private static final Log log = LogFactory.getLog(JWTSignatureValidationUtils.class);

    private static final String JWKS_URI = "jwksUri";
    private static final String JWKS_VALIDATION_ENABLE_CONFIG = "JWTValidatorConfigs.Enable";
    private static final String ENFORCE_CERTIFICATE_VALIDITY
            = "JWTValidatorConfigs.EnforceCertificateExpiryTimeValidity";

    /**
     * Method to validate the signature of the JWT.
     *
     * @param signedJWT signed JWT whose signature is to be verified.
     * @param idp       Identity provider who issued the signed JWT.
     * @return whether signature is valid, true if valid else false.
     * @throws JOSEException         Error when verifying the signature.
     * @throws IdentityOAuth2Exception Error when getting the JWKS endpoint.
     */
    public static boolean validateSignature(SignedJWT signedJWT, IdentityProvider idp)
            throws JOSEException, IdentityOAuth2Exception {

        String jwksUri = getJWKSUri(idp);

        if (isJWKSEnabled() && (jwksUri != null)) {
            return validateUsingJWKSUri(signedJWT, jwksUri);
        } else {
            return validateUsingCertificate(signedJWT, idp);
        }
    }

    /**
     * Method to check whether the JWKS is enabled.
     *
     * @return boolean value depending on whether the JWKS is enabled.
     */
    private static boolean isJWKSEnabled() {

        boolean isJWKSEnabled;
        String isJWKSEnalbedProperty = IdentityUtil.getProperty(JWKS_VALIDATION_ENABLE_CONFIG);
        isJWKSEnabled = Boolean.parseBoolean(isJWKSEnalbedProperty);
        if (isJWKSEnabled) {
            if (log.isDebugEnabled()) {
                log.debug("JWKS based JWT validation enabled.");
            }
        }
        return isJWKSEnabled;
    }

    /**
     * Method to get the JWKS Uri of the identity provider.
     *
     * @param idp Identity provider to get the JWKS Uri.
     * @return JWKS Uri of the identity provider.
     */
    private static String getJWKSUri(IdentityProvider idp) {

        String jwksUri = null;

        IdentityProviderProperty[] identityProviderProperties = idp.getIdpProperties();
        if (!ArrayUtils.isEmpty(identityProviderProperties)) {
            for (IdentityProviderProperty identityProviderProperty : identityProviderProperties) {
                if (StringUtils.equals(identityProviderProperty.getName(), JWKS_URI)) {
                    jwksUri = identityProviderProperty.getValue();
                    if (log.isDebugEnabled()) {
                        log.debug("JWKS endpoint set for the identity provider : " + idp.getIdentityProviderName() +
                                ", jwks_uri : " + jwksUri);
                    }
                    break;
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("JWKS endpoint not specified for the identity provider : " + idp
                                .getIdentityProviderName());
                    }
                }
            }
        }

        return jwksUri;
    }

    /**
     * Method to validate the signature using JWKS Uri.
     *
     * @param signedJWT Signed JWT whose signature is to be validated.
     * @param jwksUri   JWKS Uri of the identity provider.
     * @return boolean value depending on the success of the validation.
     * @throws IdentityOAuth2Exception
     */
    public static boolean validateUsingJWKSUri(SignedJWT signedJWT, String jwksUri) throws IdentityOAuth2Exception {

        JWKSBasedJWTValidator jwksBasedJWTValidator = new JWKSBasedJWTValidator();
        return jwksBasedJWTValidator.validateSignature(signedJWT.getParsedString(), jwksUri, signedJWT.getHeader
                ().getAlgorithm().getName(), null);
    }

    /**
     * Method to validate the signature using certificate
     *
     * @param signedJWT Signed JWT whose signature is to be validated.
     * @param idp       Identity provider to get the certificate.
     * @return boolean value depending on the success of the validation.
     * @throws IdentityOAuth2Exception
     * @throws JOSEException
     */
    private static boolean validateUsingCertificate(SignedJWT signedJWT, IdentityProvider idp)
            throws IdentityOAuth2Exception, JOSEException {

        JWSVerifier verifier = null;
        JWSHeader header = signedJWT.getHeader();
        X509Certificate x509Certificate = resolveSignerCertificate(header, idp);
        if (x509Certificate == null) {
            handleClientException(
                    "Unable to locate certificate for Identity Provider " + idp.getDisplayName() + "; JWT " +
                            header.toString());
        }

        checkValidity(x509Certificate);

        String alg = signedJWT.getHeader().getAlgorithm().getName();
        if (StringUtils.isEmpty(alg)) {
            handleClientException("Algorithm must not be null.");
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Signature Algorithm found in the JWT Header: " + alg);
            }
            if (alg.startsWith("RS")) {
                // At this point 'x509Certificate' will never be null.
                PublicKey publicKey = x509Certificate.getPublicKey();
                if (publicKey instanceof RSAPublicKey) {
                    verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
                } else {
                    handleClientException("Public key is not an RSA public key.");
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Signature Algorithm not supported yet : " + alg);
                }
            }
            if (verifier == null) {
                handleServerException("Could not create a signature verifier for algorithm type: " + alg);
            }
        }

        // At this point 'verifier' will never be null.
        return signedJWT.verify(verifier);
    }

    /**
     * Check the validity of the x509Certificate.
     *
     * @param x509Certificate x509Certificate.
     * @throws IdentityOAuth2Exception
     */
    private static void checkValidity(X509Certificate x509Certificate) throws IdentityOAuth2Exception {

        String isEnforceCertificateValidity = IdentityUtil.getProperty(ENFORCE_CERTIFICATE_VALIDITY);
        if (StringUtils.isNotEmpty(isEnforceCertificateValidity)
                && !Boolean.parseBoolean(isEnforceCertificateValidity)) {
            if (log.isDebugEnabled()) {
                log.debug("Check for the certificate validity is disabled.");
            }
            return;
        }

        try {
            x509Certificate.checkValidity();
        } catch (CertificateExpiredException e) {
            throw new IdentityOAuth2Exception("X509Certificate has expired.", e);
        } catch (CertificateNotYetValidException e) {
            throw new IdentityOAuth2Exception("X509Certificate is not yet valid.", e);
        }
    }

    /**
     * The default implementation resolves one certificate to Identity Provider and ignores the JWT header.
     * Override this method, to resolve and enforce the certificate in any other way
     * such as x5t attribute of the header.
     *
     * @param header The JWT header. Some of the x attributes may provide certificate information.
     * @param idp    The identity provider, if you need it.
     * @return the resolved X509 Certificate, to be used to validate the JWT signature.
     * @throws IdentityOAuth2Exception something goes wrong.
     */
    protected static X509Certificate resolveSignerCertificate(JWSHeader header,
                                                              IdentityProvider idp) throws IdentityOAuth2Exception {

        X509Certificate x509Certificate = null;
        try {
            x509Certificate = (X509Certificate) IdentityApplicationManagementUtil
                    .decodeCertificate(idp.getCertificate());
        } catch (CertificateException e) {
            handleServerException("Error occurred while decoding public certificate of Identity Provider "
                    + idp.getIdentityProviderName());
        }
        return x509Certificate;
    }

    /**
     * Method to handle the exceptions occurred due to client errors.
     *
     * @param errorMessage
     * @throws IdentityOAuth2ClientException
     */
    private static void handleClientException(String errorMessage) throws IdentityOAuth2ClientException {

        if (log.isDebugEnabled()) {
            log.debug(errorMessage);
        }
        throw new IdentityOAuth2ClientException(errorMessage);
    }

    /**
     * Method to handle the exceptions occurred due to server errors.
     *
     * @param errorMessage
     * @throws IdentityOAuth2ServerException
     */
    private static void handleServerException(String errorMessage) throws IdentityOAuth2ServerException {

        log.error(errorMessage);
        throw new IdentityOAuth2ServerException(errorMessage);
    }
}
