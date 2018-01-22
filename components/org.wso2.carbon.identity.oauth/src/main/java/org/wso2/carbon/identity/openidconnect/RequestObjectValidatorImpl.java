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
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.ReadOnlyJWSHeader;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.openidconnect.model.Constants;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import static org.apache.commons.lang.StringUtils.isEmpty;
import static org.wso2.carbon.identity.openidconnect.model.Constants.DASH_DELIMITER;
import static org.wso2.carbon.identity.openidconnect.model.Constants.FULL_STOP_DELIMITER;
import static org.wso2.carbon.identity.openidconnect.model.Constants.KEYSTORE_FILE_EXTENSION;
import static org.wso2.carbon.identity.openidconnect.model.Constants.RS;

/**
 * This class validates request object parameter value which comes with the OIDC authorization request as an optional
 * parameter
 */

public class RequestObjectValidatorImpl implements RequestObjectValidator {

    private static Log log = LogFactory.getLog(RequestObjectValidatorImpl.class);

    @Override
    public boolean isSigned(RequestObject requestObject) {
        return requestObject.getSignedJWT() != null;
    }

    @Override
    public boolean validateSignature(RequestObject requestObject, OAuth2Parameters oAuth2Parameters) throws
            RequestObjectException {
        SignedJWT jwt = requestObject.getSignedJWT();
        Certificate certificate = getCertificateForAlias(oAuth2Parameters.getTenantDomain(), oAuth2Parameters
                .getClientId());
        boolean isVerified = isSignatureVerified(jwt, certificate);
        requestObject.setIsSignatureValid(isVerified);
        return isVerified;
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
        if (isParamPresent(requestObject, Constants.REQUEST_URI)) {
            isValid = false;
        } else if (isParamPresent(requestObject, Constants.REQUEST)) {
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
     * @return tokenEndpoint of the Issuer
     * @throws IdentityOAuth2Exception
     */
    public static String getTokenEpURL(String tenantDomain) throws RequestObjectException {
        String tokenEndpoint;
        IdentityProvider residentIdP;
        try {
            residentIdP = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
            FederatedAuthenticatorConfig oidcFedAuthn = IdentityApplicationManagementUtil
                    .getFederatedAuthenticator(residentIdP.getFederatedAuthenticatorConfigs(),
                            IdentityApplicationConstants.Authenticator.OIDC.NAME);
            tokenEndpoint = IdentityApplicationManagementUtil.getProperty(oidcFedAuthn.getProperties(),
                    IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_TOKEN_URL).getValue();
            if (log.isDebugEnabled()) {
                log.debug("Found Token Endpoint URL: " + tokenEndpoint);
            }
        } catch (IdentityProviderManagementException e) {
            log.error("Error while loading OAuth2TokenEPUrl of the resident IDP of tenant:" + tenantDomain, e);
            throw new RequestObjectException(OAuth2ErrorCodes.SERVER_ERROR, "Server Error while validating audience " +
                    "of Request Object.");
        }

        if (isEmpty(tokenEndpoint)) {
            tokenEndpoint = IdentityUtil.getServerURL(IdentityConstants.OAuth.TOKEN, true, false);
        }
        return tokenEndpoint;
    }

    private boolean isValidIssuer(RequestObject requestObject, OAuth2Parameters oAuth2Parameters) {
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
    public boolean validateAudience(String currentAudience, List<String> audience) {
        for (String aud : audience) {
            if (StringUtils.equals(currentAudience, aud)) {
                return true;
            }
        }
        return logAndReturnFalse("None of the audience values matched the tokenEndpoint Alias:" + currentAudience);
    }

    /**
     * Get the X509CredentialImpl object for a particular tenant and alias
     *
     * @param tenantDomain tenant domain of the issuer
     * @param alias        alias of cert
     * @return X509Certificate object containing the public certificate in the primary keystore of the tenantDOmain
     * with alias
     */
    protected Certificate getCertificateForAlias(String tenantDomain, String alias) throws RequestObjectException {

        int tenantId;
        String error = "Unable to Validate the Signature of Request Object";
        tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        KeyStoreManager keyStoreManager;
        // get an instance of the corresponding Key Store Manager instance
        keyStoreManager = KeyStoreManager.getInstance(tenantId);
        KeyStore keyStore;
        try {
            if (tenantId != MultitenantConstants.SUPER_TENANT_ID) {// for tenants, load key from their generated key store
                keyStore = keyStoreManager.getKeyStore(generateKSNameFromDomainName(tenantDomain));
            } else {
                // for super tenant, load the default pub. cert using the config. in carbon.xml
                keyStore = keyStoreManager.getPrimaryKeyStore();
            }
            return keyStore.getCertificate(alias);

        } catch (KeyStoreException e) {
            String errorMsg = "Error instantiating an X509Certificate object for the certificate alias:" + alias +
                    " in tenant:" + tenantDomain;
            log.error(errorMsg, e);
            throw new RequestObjectException(OAuth2ErrorCodes.SERVER_ERROR, error);
        } catch (Exception e) {
            //keyStoreManager throws Exception
            log.error("Unable to load key store manager for the tenant domain:" + tenantDomain, e);
            throw new RequestObjectException(OAuth2ErrorCodes.SERVER_ERROR, error);
        }
    }

    /**
     * Generate the key store name from the domain name
     *
     * @param tenantDomain tenant domain name
     * @return key store file name
     */
    public static String generateKSNameFromDomainName(String tenantDomain) {
        String ksName = tenantDomain.trim().replace(FULL_STOP_DELIMITER, DASH_DELIMITER);
        return ksName + KEYSTORE_FILE_EXTENSION;
    }

    /**
     * Validate the signedJWT signature with given certificate
     *
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

