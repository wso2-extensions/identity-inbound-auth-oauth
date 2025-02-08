/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.validators.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import java.net.MalformedURLException;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.wso2.carbon.identity.openidconnect.model.Constants.PS;
import static org.wso2.carbon.identity.openidconnect.model.Constants.RS;

/**
 * Validate JWT using Identity Provider's jwks_uri.
 */
public class JWKSBasedJWTValidator implements JWTValidator {

    private static final Log log = LogFactory.getLog(JWKSBasedJWTValidator.class);
    private ConfigurableJWTProcessor<SecurityContext> jwtProcessor;
    private static final String ENFORCE_CERTIFICATE_VALIDITY
            = "JWTValidatorConfigs.EnforceCertificateExpiryTimeValidity";

    public JWKSBasedJWTValidator() {
        /* Set up a JWT processor to parse the tokens and then check their signature and validity time window
        (bounded by the "iat", "nbf" and "exp" claims). */
        this.jwtProcessor = new DefaultJWTProcessor<>();
    }

    @Override
    public boolean validateSignature(String jwtString, String jwksUri, String algorithm, Map<String, Object> opts)
            throws IdentityOAuth2Exception {

        try {
            JWT jwt = JWTParser.parse(jwtString);
            if (!checkCertificateValidity(jwksUri, (SignedJWT) jwt)) {
                return false;
            }
            return this.validateSignature(jwt, jwksUri, algorithm, opts);

        } catch (ParseException e) {
            throw new IdentityOAuth2Exception("Error occurred while parsing JWT string.", e);
        } catch (BadJOSEException e) {
            throw new IdentityOAuth2Exception("Signature validation failed for the provided JWT.", e);
        } catch (MalformedURLException e) {
            throw new IdentityOAuth2Exception("Provided jwks_uri: " + jwksUri + " is malformed.", e);
        } catch (KeySourceException e) {
            log.error("Error occurred while accessing remote JWKS endpoint: " + jwksUri, e);
            throw new IdentityOAuth2Exception("Error occurred while accessing remote JWKS endpoint: " + jwksUri, e);
        } catch (CertificateNotYetValidException e) {
            throw new IdentityOAuth2Exception("X509Certificate is not yet valid.", e);
        } catch (CertificateExpiredException e) {
            throw new IdentityOAuth2Exception("X509Certificate has expired.", e);
        }
    }

    /**
     * Check the expiry time validity (i.e. expired, not yet valid) of the X509Certificate derived from
     * the "x5c" parameter in the retrieved JWKS.
     * See {@link <a href="https://tools.ietf.org/html/rfc7517#section-4.7}">x5c parameter</a>}
     *
     * @param jwksUri URI of the JWKS endpoint
     * @param jwt     Signed JWT
     * @throws MalformedURLException           If the provided JWKS URI is not valid.
     * @throws RemoteKeySourceException        If the remote JWKS endpoint could not be accessed.
     * @throws CertificateNotYetValidException If X509Certificate decoded from the "x5c" parameter is not yet valid.
     * @throws CertificateExpiredException     If X509Certificate decoded from the "x5c" parameter is expired.
     * @throws KeySourceException              If remote JWK, or matching keys set was not found in the given JWKS.
     * @throws BadJOSEException                If the keyId of the JWS header is null (i.e. due to a bad signature.)
     */
    private boolean checkCertificateValidity(String jwksUri, SignedJWT jwt) throws MalformedURLException,
            CertificateNotYetValidException, CertificateExpiredException, KeySourceException, BadJOSEException {

        String isEnforceCertificateValidity = IdentityUtil.getProperty(ENFORCE_CERTIFICATE_VALIDITY);
        if (StringUtils.isNotEmpty(isEnforceCertificateValidity)
                && !Boolean.parseBoolean(isEnforceCertificateValidity)) {
            if (log.isDebugEnabled()) {
                log.debug("Check for the certificate validity is disabled.");
            }
            return true;
        }

        X509Certificate x509Certificate = null;
        List<JWK> matchingJWKs;
        RemoteJWKSet<SecurityContext> remoteJWKSet = JWKSourceDataProvider.getInstance().getJWKSource(jwksUri);
        String kid = Optional.ofNullable(jwt.getHeader()).map(JWSHeader::getKeyID).orElse(null);

        if (kid == null) {
            throw new BadJOSEException("Value of the \"kid\" property in JWS header is null.");
        }

        if (remoteJWKSet != null) {
            matchingJWKs = remoteJWKSet.get(new JWKSelector(
                    new JWKMatcher.Builder()
                            .keyID(kid)
                            .build()
            ), null);
            if (CollectionUtils.isNotEmpty(matchingJWKs)) {
                if (log.isDebugEnabled()) {
                    log.debug("Matching key found in JWKS endpoint: " + jwksUri);
                }
                JWK key = matchingJWKs.get(0);

                if (CollectionUtils.isNotEmpty(key.getX509CertChain())) {
                    x509Certificate = X509CertUtils.parse(key.getX509CertChain().get(0).decode());
                } else if (log.isDebugEnabled()) {
                    log.debug("x5c parameter is undefined in JWK having the kid: " + kid);
                }
            } else {
                throw new KeySourceException("No matching keys found in JWKS endpoint: " + jwksUri);
            }

            if (x509Certificate != null) {

                String alg = jwt.getHeader().getAlgorithm().getName();
                if (log.isDebugEnabled()) {
                    log.debug("Signature Algorithm found in the JWT Header: " + alg);
                }

                if (!isValidCertificate(x509Certificate, alg)) {
                    return false;
                }
                x509Certificate.checkValidity();
            } else if (log.isDebugEnabled()) {
                log.debug("X509Certificate is null. Hence, certificate expiry date validation is skipped.");
            }
        } else {
            throw new KeySourceException("Remote JWK set not found in the JWKS endpoint: " + jwksUri);
        }
        return true;
    }

    @Override
    public boolean validateSignature(JWT jwt, String jwksUri, String algorithm, Map<String, Object> opts) throws
            IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("validating JWT signature using jwks_uri: " + jwksUri + " , for signing algorithm: " +
                    algorithm);
        }
        try {
            // set the Key Selector for the jwks_uri.
            setJWKeySelector(jwksUri, algorithm);

            // Process the token, set optional context parameters.
            SecurityContext securityContext = null;
            if (MapUtils.isNotEmpty(opts)) {
                securityContext = new SimpleSecurityContext();
                ((SimpleSecurityContext) securityContext).putAll(opts);
            }

            if (jwt instanceof PlainJWT) {
                jwtProcessor.process((PlainJWT) jwt, securityContext);
            } else if (jwt instanceof SignedJWT) {
                jwtProcessor.process((SignedJWT) jwt, securityContext);
            } else if (jwt instanceof EncryptedJWT) {
                jwtProcessor.process((EncryptedJWT) jwt, securityContext);
            } else {
                jwtProcessor.process(jwt, securityContext);
            }
            return true;

        } catch (MalformedURLException e) {
            throw new IdentityOAuth2Exception("Provided jwks_uri is malformed.", e);
        } catch (JOSEException e) {
            throw new IdentityOAuth2Exception("Signature validation failed for the provided JWT.", e);
        } catch (BadJOSEException e) {
            throw new IdentityOAuth2Exception("Signature validation failed for the provided JWT", e);
        }
    }

    private void setJWKeySelector(String jwksUri, String algorithm) throws MalformedURLException {

        /* The public RSA keys to validate the signatures will be sourced from the OAuth 2.0 server's JWK set,
        published at a well-known URL. The RemoteJWKSet object caches the retrieved keys to speed up subsequent
        look-ups and can also gracefully handle key-rollover. */
        JWKSource<SecurityContext> keySource = JWKSourceDataProvider.getInstance().getJWKSource(jwksUri);

        // The expected JWS algorithm of the access tokens (agreed out-of-band).
        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.parse(algorithm);

        /* Configure the JWT processor with a key selector to feed matching public RSA keys sourced from the JWK set
        URL. */
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);
        jwtProcessor.setJWSKeySelector(keySelector);
    }

    /**
     * Validate the certificate based on the signature algorithm.
     *
     * @param x509Certificate X509Certificate
     * @param alg             Signature Algorithm
     * @return true if the certificate is valid.
     */
    private boolean isValidCertificate(X509Certificate x509Certificate, String alg) {

        if (alg.startsWith(RS) || alg.startsWith(PS)) {
            // At this point 'x509Certificate' will never be null.
            PublicKey publicKey = x509Certificate.getPublicKey();
            if (publicKey instanceof RSAPublicKey) {
                return true;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Public key is not an RSA public key.");
                }
                return false;
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Signature Algorithm not supported yet: " + alg);
            }
            return false;
        }
    }
}
