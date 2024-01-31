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

package org.wso2.carbon.identity.oauth2.validators;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.JWTUtils;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Optional;

/**
 * JWT Access token validator
 */
public class OAuth2JWTTokenValidator extends DefaultOAuth2TokenValidator {

    private static final Log log = LogFactory.getLog(OAuth2JWTTokenValidator.class);
    private static final String TRUE = "true";

    @Override
    public boolean validateAccessToken(OAuth2TokenValidationMessageContext validationReqDTO)
            throws IdentityOAuth2Exception {

        if (!JWTUtils.isJWT(validationReqDTO.getRequestDTO().getAccessToken().getIdentifier())) {
            return false;
        }
        try {
            SignedJWT signedJWT = getSignedJWT(validationReqDTO);
            Optional<JWTClaimsSet> claimsSet = JWTUtils.getJWTClaimSet(signedJWT);
            if (!claimsSet.isPresent()) {
                LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, null,
                        OAuthConstants.LogConstants.FAILED, "Claim values are empty in the provided token.",
                        "validate-jwt-access-token", null);
                throw new IdentityOAuth2Exception("Claim values are empty in the given Token.");
            }

            if (!JWTUtils.validateRequiredFields(claimsSet.get())) {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, null,
                            OAuthConstants.LogConstants.FAILED,
                            "Mandatory fields (iss, sub, exp, jtl, aud) are empty in the provided token.",
                            "validate-jwt-access-token", null);
                }
                return false;
            }

            // Derive signing tenant domain for identity provider
            AccessTokenDO accessTokenDO = (AccessTokenDO) validationReqDTO.getProperty(OAuthConstants.ACCESS_TOKEN_DO);
            String tenantDomain = JWTUtils.getSigningTenantDomain(claimsSet.get(), accessTokenDO);
            if (log.isDebugEnabled()) {
                log.debug("Resolved tenant domain: " + tenantDomain + " to validate the JWT access token.");
            }

            IdentityProvider identityProvider = JWTUtils.getResidentIDPForIssuer(claimsSet.get(), tenantDomain);

            if (!validateSignature(signedJWT, identityProvider)) {
                LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, null,
                        OAuthConstants.LogConstants.FAILED, "Signature validation failed.", "validate-jwt-access-token",
                        null);
                return false;
            }
            if (!JWTUtils.checkExpirationTime(claimsSet.get().getExpirationTime())) {
                LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, null,
                        OAuthConstants.LogConstants.FAILED, "Token is expired.", "validate-jwt-access-token", null);
                return false;
            }
            JWTUtils.checkNotBeforeTime(claimsSet.get().getNotBeforeTime());
            setJWTMessageContext(validationReqDTO, claimsSet.get());
        } catch (JOSEException | ParseException e) {
            LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, null,
                    OAuthConstants.LogConstants.FAILED, "System error occurred.", "validate-jwt-access-token", null);
            throw new IdentityOAuth2Exception("Error while validating Token.", e);
        }
        LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, null,
                OAuthConstants.LogConstants.SUCCESS, "Token validation is successful.", "validate-jwt-access-token",
                null);
        return true;
    }

    @Override
    public String getTokenType() {

        return "JWT";
    }

    /**
     * The default implementation resolves one certificate to Identity Provider and ignores the JWT header.
     * Override this method, to resolve and enforce the certificate in any other way
     * such as x5t attribute of the header.
     *
     * @param header The JWT header. Some x attributes may provide certificate information.
     * @param idp    The identity provider, if you need it.
     * @return the resolved X509 Certificate, to be used to validate the JWT signature.
     * @throws IdentityOAuth2Exception something goes wrong.
     */
    protected X509Certificate resolveSignerCertificate(JWSHeader header,
                                                       IdentityProvider idp) throws IdentityOAuth2Exception {
        return JWTUtils.resolveSignerCertificate(idp);
    }

    /**
     * Parse JWT.
     *
     * @param validationReqDTO Token Validation Request
     * @return SignedJWT
     * @throws ParseException if an error occurs while parsing
     */
    private SignedJWT getSignedJWT(OAuth2TokenValidationMessageContext validationReqDTO) throws ParseException {

        return JWTUtils.parseJWT(validationReqDTO.getRequestDTO().getAccessToken().getIdentifier());
    }

    private boolean validateSignature(SignedJWT signedJWT, IdentityProvider idp)
            throws JOSEException, IdentityOAuth2Exception, ParseException {

        X509Certificate x509Certificate;
        JWSHeader header = signedJWT.getHeader();
        JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();

        // Get certificate from tenant if available in claims.
        Optional<X509Certificate> certificate = JWTUtils.getCertificateFromClaims(jwtClaimsSet);
        if (certificate.isPresent()) {
            x509Certificate = certificate.get();
        } else {
            x509Certificate = resolveSignerCertificate(header, idp);
        }
        if (x509Certificate == null) {
            throw new IdentityOAuth2Exception("Unable to locate certificate for Identity Provider: "
                    + idp.getDisplayName());
        }
        String algorithm = JWTUtils.verifyAlgorithm(signedJWT);
        return JWTUtils.verifySignature(signedJWT, x509Certificate, algorithm);
    }

    private void setJWTMessageContext(OAuth2TokenValidationMessageContext validationReqDTO, JWTClaimsSet claimsSet) {

        validationReqDTO.addProperty(OAuth2Util.JWT_ACCESS_TOKEN, TRUE);
        validationReqDTO.addProperty(OAuth2Util.SUB, claimsSet.getSubject());
        validationReqDTO.addProperty(OAuth2Util.ISS, claimsSet.getIssuer());
        validationReqDTO.addProperty(OAuth2Util.AUD, String.join(",", claimsSet.getAudience()));
        validationReqDTO.addProperty(OAuth2Util.JTI, claimsSet.getJWTID());
    }
}
