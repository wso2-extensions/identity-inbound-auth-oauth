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
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import java.net.MalformedURLException;
import java.text.ParseException;
import java.util.Map;

/**
 * Validate JWT using Identity Provider's jwks_uri.
 */
public class JWKSBasedJWTValidator implements JWTValidator {

    private static final Log log = LogFactory.getLog(JWKSBasedJWTValidator.class);
    private ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

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
            return this.validateSignature(jwt, jwksUri, algorithm, opts);

        } catch (ParseException e) {
            throw new IdentityOAuth2Exception("Error occurred while parsing JWT string.", e);
        }
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
                ((SimpleSecurityContext)securityContext).putAll(opts);
            }

          if (jwt instanceof PlainJWT) {
                jwtProcessor.process((PlainJWT)jwt, securityContext);
            } else if (jwt instanceof SignedJWT) {
                jwtProcessor.process((SignedJWT)jwt, securityContext);
            } else if (jwt instanceof EncryptedJWT) {
                jwtProcessor.process((EncryptedJWT)jwt, securityContext);
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
}
