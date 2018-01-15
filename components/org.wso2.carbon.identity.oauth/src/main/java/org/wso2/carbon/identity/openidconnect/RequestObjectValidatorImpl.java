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
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.ReadOnlyJWSHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.model.Constants;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.List;
import java.util.Properties;

import static org.apache.commons.lang.StringUtils.isEmpty;

/**
 * This class validates request object parameter value which comes with the OIDC authorization request as an optional
 * parameter
 */

public class RequestObjectValidatorImpl implements RequestObjectValidator {

    private static Log log = LogFactory.getLog(RequestObjectValidatorImpl.class);
    //JWS is consists of three parts seperated by 2 '.'s as JOSE header, JWS payload, JWS signature
    private static final int NUMBER_OF_PARTS_IN_JWS = 3;
    private static final String RS = "RS";
    public static final String JWT_PART_DELIMITER = "\\.";

    public static final String FULL_STOP_DELIMITER = ".";
    private static Properties properties;

    @Override
    public boolean isEncrypted(String requestObject) {
        try {
            EncryptedJWT encryptedJWT = EncryptedJWT.parse(requestObject);
            return true;
        } catch (ParseException e) {
            return false;
        }
    }

    @Override
    public boolean isSigned(RequestObject requestObject) {
        return requestObject.getSignedJWT() != null;
    }

    @Override
    public boolean validateSignature(RequestObject requestObject, String alias) throws RequestObjectException {
        SignedJWT jwt = requestObject.getSignedJWT();
        Certificate certificate = getCertificateForAlias(alias);
        boolean isVerified = isSignatureVerified(jwt, certificate);
        requestObject.setIsSignatureValid(isVerified);
        return isVerified;
    }


    /**
     * Decrypt the request object.
     *
     * @param requestObject    requestObject
     * @param oAuth2Parameters oAuth2Parameters
     * @throws RequestObjectException
     */
    @Override
    public String decrypt(String requestObject, OAuth2Parameters oAuth2Parameters) throws RequestObjectException {

        EncryptedJWT encryptedJWT;
        try {
            encryptedJWT = EncryptedJWT.parse(requestObject);
            RSAPrivateKey rsaPrivateKey = getRsaPrivateKey(oAuth2Parameters);
            RSADecrypter decrypter = new RSADecrypter(rsaPrivateKey);
            encryptedJWT.decrypt(decrypter);

            JWEObject jweObject = JWEObject.parse(requestObject);
            jweObject.decrypt(decrypter);

            if (jweObject != null && jweObject.getPayload() != null && jweObject.getPayload().toString()
                    .split(JWT_PART_DELIMITER).length == NUMBER_OF_PARTS_IN_JWS) {
                return jweObject.getPayload().toString();
            } else {
                return new PlainJWT((JWTClaimsSet) encryptedJWT.getJWTClaimsSet()).serialize();
            }

        } catch (JOSEException | IdentityOAuth2Exception | java.text.ParseException e) {
            throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, "Failed to decrypt " +
                    "request object.");
        }
    }

    private RSAPrivateKey getRsaPrivateKey(OAuth2Parameters oAuth2Parameters) throws IdentityOAuth2Exception {
        String tenantDomain = getTenantDomainForDecryption(oAuth2Parameters);
        int tenantId = OAuth2Util.getTenantId(tenantDomain);
        Key key = OAuth2Util.getPrivateKey(tenantDomain, tenantId);
        return (RSAPrivateKey) key;
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
        boolean isValid = validateClientIdAndResponseType(requestObject, oAuth2Parameters);
        if (notEmpty(requestObject, Constants.REQUEST_URI)) {
            isValid = false;
        } else if (notEmpty(requestObject, Constants.REQUEST)) {
            isValid = false;
        } else if (requestObject.isSigned()) {
            isValid = isValidIssuer(requestObject, oAuth2Parameters) && isValidAudience(requestObject, oAuth2Parameters);
        }
        return isValid;
    }

    private boolean isValidAudience(RequestObject requestObject, OAuth2Parameters oAuth2Parameters) throws RequestObjectException {
        String tokenEPUrl = getTokenEpURL(oAuth2Parameters.getTenantDomain());
        List<String> audience = requestObject.getClaimsSet().getAudience();
        return validateAudience(tokenEPUrl, audience);
    }

    private static boolean validateClientIdAndResponseType(RequestObject requestObject, OAuth2Parameters oauthRequest)
            throws RequestObjectException {
        String clientIdInReqObj = requestObject.getClaimValue(Constants.CLIENT_ID);
        String responseTypeInReqObj = requestObject.getClaimValue(Constants.RESPONSE_TYPE);
        String errorMsg = "Request Object and Authorization request contains unmatched ";

        if (!isValidParameter(oauthRequest.getClientId(), clientIdInReqObj)) {
            throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, errorMsg + Constants.CLIENT_ID);
        }

        if (!isValidParameter(oauthRequest.getResponseType(), responseTypeInReqObj)) {
            throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST,
                    errorMsg + Constants.RESPONSE_TYPE);
        }
        return true;
    }


    private static boolean isValidParameter(String authParam, String requestObjParam) {
        return StringUtils.isEmpty(requestObjParam) || requestObjParam.equals(authParam);
    }

    /**
     * Return globally set audience or the token endpoint of the server
     *
     * @param tenantDomain
     * @return
     * @throws IdentityOAuth2Exception
     */
    public static String getTokenEpURL(String tenantDomain) throws RequestObjectException {
        String audience = null;
        IdentityProvider residentIdP;
        try {
            residentIdP = IdentityProviderManager.getInstance()
                    .getResidentIdP(tenantDomain);
            FederatedAuthenticatorConfig oidcFedAuthn = IdentityApplicationManagementUtil
                    .getFederatedAuthenticator(residentIdP.getFederatedAuthenticatorConfigs(),
                            IdentityApplicationConstants.Authenticator.OIDC.NAME);
            audience = IdentityApplicationManagementUtil.getProperty(oidcFedAuthn.getProperties(),
                    IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_TOKEN_URL).getValue();
        } catch (IdentityProviderManagementException e) {
            log.error("Error while loading OAuth2TokenEPUrl of the resident IDP of tenant:" + tenantDomain, e);
            throw new RequestObjectException(OAuth2ErrorCodes.SERVER_ERROR, "Server Error while validating audience " +
                    "of Request Object.");
        }

        if (isEmpty(audience)) {
            audience = IdentityUtil.getServerURL(IdentityConstants.OAuth.TOKEN, true, false);
        }
        return audience;
    }

    private boolean isValidIssuer(RequestObject requestObject, OAuth2Parameters oAuth2Parameters) {
        String issuer = requestObject.getClaimsSet().getIssuer();
        return StringUtils.isNotEmpty(issuer) && issuer.equals(oAuth2Parameters.getClientId());
    }

    private boolean notEmpty(RequestObject requestObject, String claim) {
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
    public boolean validateAudience(String currentAudience, List<String> audience) {
        for (String aud : audience) {
            if (StringUtils.equals(currentAudience, aud)) {
                return true;
            }
        }
        return logAndReturnFalse("None of the audience values matched the tokenEndpoint Alias:" + currentAudience);
    }

    /**
     * Get tenant domain from oAuth2Parameters.
     *
     * @param oAuth2Parameters oAuth2Parameters
     * @return Tenant domain
     */
    private String getTenantDomainForDecryption(OAuth2Parameters oAuth2Parameters) {
        if (StringUtils.isNotEmpty(oAuth2Parameters.getTenantDomain())) {
            return oAuth2Parameters.getTenantDomain();
        }
        return MultitenantConstants.SUPER_TENANT_NAME;
    }

    /**
     * Get the certificate which matches the given alias from client-truststore
     * @param alias
     * @return
     * @throws RequestObjectException
     */
    private Certificate getCertificateForAlias(String alias) throws RequestObjectException {
        Certificate certificate;
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(new FileInputStream(buildFilePath(getPropertyValue(OAuthConstants.CLIENT_TRUST_STORE))),
                    getPropertyValue(OAuthConstants.CLIENT_TRUST_STORE_PASSWORD).toCharArray());
            certificate = keyStore.getCertificate(alias);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            String errorMsg = "Error while loading a certificate to validate the request object signature.";
            if (log.isDebugEnabled()) {
                log.error(errorMsg, e);
            }
            throw new RequestObjectException(OAuth2ErrorCodes.SERVER_ERROR, errorMsg);
        }
        return certificate;
    }

    /**
     * Validate the signedJWT signature with given certificate
     * @param signedJWT
     * @param x509Certificate
     * @return
     */
    private boolean isSignatureVerified(SignedJWT signedJWT, Certificate x509Certificate) {

        JWSVerifier verifier;
        ReadOnlyJWSHeader header = signedJWT.getHeader();
        if (x509Certificate == null) {
            return logAndReturnFalse("Unable to locate certificate for JWT " + header.toString());
        }

        String alg = signedJWT.getHeader().getAlgorithm().getName();
        if (isEmpty(alg)) {
            return false;
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Signature Algorithm found in the JWT Header: " + alg);
            }
            if (alg.indexOf(RS) == 0) {
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

    /**
     * Build the absolute path of a give file path
     *
     * @param path File path
     * @return Absolute file path
     */
    private static String buildFilePath(String path) {

        if (StringUtils.isNotEmpty(path) && path.startsWith(FULL_STOP_DELIMITER)) {
            // Relative file path is given
            File currentDirectory = new File(new File(FULL_STOP_DELIMITER)
                    .getAbsolutePath());
            try {
                path = currentDirectory.getCanonicalPath() + File.separator + path;
            } catch (IOException e) {
                log.error("Error occurred while retrieving current directory path");
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("File path for TrustStore : " + path);
        }
        return path;
    }

    /**
     * Get property value by key
     *
     * @param key Property key
     * @return Property value
     */
    private static String getPropertyValue(String key) throws IOException {

        if (properties == null) {
            properties = new Properties();
            String configFilePath = buildFilePath(OAuthConstants.CONFIG_RELATIVE_PATH);
            File configFile = new File(configFilePath);
            InputStream inputStream = new FileInputStream(configFile);
            properties.load(inputStream);
        }
        return properties.getProperty(key);
    }
}

