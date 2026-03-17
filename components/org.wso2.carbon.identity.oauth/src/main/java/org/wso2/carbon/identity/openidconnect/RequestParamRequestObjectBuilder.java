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
import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;
import org.wso2.carbon.utils.DiagnosticLog;

import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;

import static org.apache.commons.lang.StringUtils.isEmpty;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.CLIENT_ID;
import static org.wso2.carbon.identity.openidconnect.model.Constants.JWT_PART_DELIMITER;
import static org.wso2.carbon.identity.openidconnect.model.Constants.NUMBER_OF_PARTS_IN_JWE;
import static org.wso2.carbon.identity.openidconnect.model.Constants.NUMBER_OF_PARTS_IN_JWS;

/**
 * This class is used to build request object parameter value which comes with the OIDC authorization request as an
 * optional parameter
 */
public class RequestParamRequestObjectBuilder implements RequestObjectBuilder {

    private static final Log log = LogFactory.getLog(RequestParamRequestObjectBuilder.class);

    /**
     * Builds request object which comes as the value of the request query parameter of OIDC authorization request
     *
     * @param requestObjectParam request object
     * @throws RequestObjectException
     */
    @Override
    public RequestObject buildRequestObject(String requestObjectParam, OAuth2Parameters oAuth2Parameters) throws
            RequestObjectException {

        RequestObject requestObject = new RequestObject();
        // Making a copy of requestObjectParam to prevent editing initial reference
        String requestObjectParamValue = requestObjectParam;
        if (isEncrypted(requestObjectParamValue)) {
            requestObjectParamValue = decrypt(requestObjectParamValue, oAuth2Parameters);
            if (isEmpty(requestObjectParamValue)) {
                return requestObject;
            }
        }
        setRequestObjectValues(requestObjectParamValue, requestObject);
        if (log.isDebugEnabled()) {
            log.debug("Request Object extracted from the request: " + requestObjectParam);
        }
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.PARSE_REQUEST_OBJECT)
                    .resultMessage("Request object parsed successfully.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS));
        }
        return requestObject;
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
            // When using an encrypted request object for par endpoint, client id and tenant domain may not be
            // available in the oauth2 parameters.
            if (StringUtils.isBlank(oAuth2Parameters.getTenantDomain())) {
                oAuth2Parameters.setTenantDomain(
                        PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain());
            }
            String applicationRequestObjectEncryptionAlgorithm;
            if (StringUtils.isNotBlank(oAuth2Parameters.getClientId())) {
                // If client id is available in the oauth2 parameters, validate encryption algorithm and method.
                validateEncryptionAlgorithmAndMethod(encryptedJWT.getHeader(), oAuth2Parameters.getClientId(),
                        oAuth2Parameters.getTenantDomain());
                OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(
                        oAuth2Parameters.getClientId(), oAuth2Parameters.getTenantDomain());
                applicationRequestObjectEncryptionAlgorithm = oAuthAppDO.getRequestObjectEncryptionAlgorithm();
            } else {
                applicationRequestObjectEncryptionAlgorithm = encryptedJWT.getHeader().getAlgorithm().getName();
            }
            JWEAlgorithm encryptionAlgorithm = JWEAlgorithm.parse(applicationRequestObjectEncryptionAlgorithm);
            // TO-DO: support ECDH Key pair introduction.
            PrivateKey privateKey = getRSAPrivateKey(oAuth2Parameters);
            JWEDecrypter decrypter = validateDecryptorMode(encryptionAlgorithm,
                    privateKey);
            encryptedJWT.decrypt(decrypter);

            JWEObject jweObject = JWEObject.parse(requestObject);
            jweObject.decrypt(decrypter);
            String requestObjectString;
            if (jweObject.getPayload() != null && jweObject.getPayload().toString()
                    .split(JWT_PART_DELIMITER).length == NUMBER_OF_PARTS_IN_JWS) {
                requestObjectString = jweObject.getPayload().toString();
            } else {
                if (encryptedJWT.getPayload() != null) {
                    String payloadJson = encryptedJWT.getPayload().toString();
                    IdentityUtil.validateJWTDepthOfJWTPayload(payloadJson);
                }
                requestObjectString = new PlainJWT(encryptedJWT.getJWTClaimsSet()).serialize();
            }
            if (StringUtils.isBlank(oAuth2Parameters.getClientId())) {
                // Retrieve client id from the decrypted request object to validate encryption algorithm and method.
                RequestObject populatedRequestObject = new RequestObject();
                setRequestObjectValues(requestObjectString, populatedRequestObject);
                String clientId = populatedRequestObject.getClaimValue(CLIENT_ID);
                if (StringUtils.isBlank(clientId)) {
                    String errorMessage = "Client ID is not found in the decrypted request object.";
                    throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, errorMessage);
                }
                validateEncryptionAlgorithmAndMethod(encryptedJWT.getHeader(), clientId,
                        oAuth2Parameters.getTenantDomain());
            }
            return requestObjectString;
        } catch (JOSEException | IdentityOAuth2Exception | ParseException | InvalidOAuthClientException e) {
            String errorMessage = "Failed to decrypt Request Object";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage + " from " + requestObject, e);
            }
            throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, errorMessage);
        }
    }

    /**
     * Validate and get the Decrypter type.
     *
     * @param encryptionAlgorithm SP configured Encryption Algorithm
     * @param privateKey          Private key
     * @return Decrypter          decryptor type
     * @throws JOSEException      Jose exception while creating decryptor
     */
    private JWEDecrypter validateDecryptorMode(JWEAlgorithm encryptionAlgorithm, PrivateKey privateKey)
            throws JOSEException {

        if (JWEAlgorithm.RSA_OAEP_384.equals(encryptionAlgorithm) ||
                JWEAlgorithm.RSA_OAEP_512.equals(encryptionAlgorithm) ||
                JWEAlgorithm.RSA_OAEP_256.equals(encryptionAlgorithm) ||
                JWEAlgorithm.RSA_OAEP.equals(encryptionAlgorithm) ||
                JWEAlgorithm.RSA1_5.equals(encryptionAlgorithm)) {
            return new RSADecrypter(privateKey);
        }
        if (encryptionAlgorithm == null) {
            log.debug("Request Object Encryption Algorithm is not found.");
        }
        // To-Do: support for ECDH algorithms
        return new RSADecrypter(privateKey);
    }

    /**
     * Validate the encryption algorithm and method of the request object JWE header against the application's
     * configured encryption algorithm and method.
     *
     * @param jweHeader    JWE Header.
     * @param clientId     Client Id.
     * @param tenantDomain Tenant Domain.
     * @throws RequestObjectException      If validation fails.
     * @throws IdentityOAuth2Exception     If an error occurs while retrieving application information.
     * @throws InvalidOAuthClientException If the client id is invalid.
     */
    private void validateEncryptionAlgorithmAndMethod(JWEHeader jweHeader, String clientId, String tenantDomain)
            throws RequestObjectException, IdentityOAuth2Exception, InvalidOAuthClientException {

        OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId, tenantDomain);
        if (StringUtils.isNotBlank(oAuthAppDO.getRequestObjectEncryptionAlgorithm())) {
            if (!jweHeader.getAlgorithm().toString().equals(oAuthAppDO.getRequestObjectEncryptionAlgorithm())) {
                String errorMessage = "Invalid request object encryption algorithm.";
                throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, errorMessage);
            }
            if (!jweHeader.getEncryptionMethod().toString().equals(oAuthAppDO.getRequestObjectEncryptionMethod())) {
                String errorMessage = "Invalid request object encryption method.";
                throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, errorMessage);
            }
        }
    }

    protected boolean isEncrypted(String requestObject) {
        return requestObject.split(JWT_PART_DELIMITER).length == NUMBER_OF_PARTS_IN_JWE;
    }

    protected RSAPrivateKey getRSAPrivateKey(OAuth2Parameters oAuth2Parameters) throws IdentityOAuth2Exception {
        String tenantDomain = getTenantDomainForDecryption(oAuth2Parameters);
        int tenantId = OAuth2Util.getTenantId(tenantDomain);
        Key key = OAuth2Util.getPrivateKey(tenantDomain, tenantId);
        return (RSAPrivateKey) key;
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

    private void setRequestObjectValues(String requestObjectString, RequestObject requestObjectInstance) throws
            RequestObjectException {

        try {
            IdentityUtil.validateX5CLength(requestObjectString);
            JOSEObject jwt = JOSEObject.parse(requestObjectString);
            if (jwt.getHeader().getAlgorithm() == null || jwt.getHeader().getAlgorithm().equals(JWSAlgorithm.NONE)) {
                requestObjectInstance.setPlainJWT(PlainJWT.parse(requestObjectString));
            } else {
                requestObjectInstance.setSignedJWT(SignedJWT.parse(requestObjectString));
            }
        } catch (ParseException e) {
            String errorMessage = "No Valid JWT is found for the Request Object.";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage + "Received Request Object: " + requestObjectString, e);
            }
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.PARSE_REQUEST_OBJECT)
                        .inputParam("request object", requestObjectString)
                        .resultMessage("Request object is not a valid JWT.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED));
            }
            throw new RequestObjectException(OAuth2ErrorCodes.INVALID_REQUEST, errorMessage);
        }
    }
}
