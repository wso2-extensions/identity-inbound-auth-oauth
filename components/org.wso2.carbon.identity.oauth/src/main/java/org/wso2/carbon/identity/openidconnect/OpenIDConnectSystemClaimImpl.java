/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.identity.openidconnect;

import com.nimbusds.jose.JWSAlgorithm;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.Charsets;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import static org.apache.commons.lang.StringUtils.isNotBlank;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.AT_HASH;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.C_HASH;

/**
 * This class is used to inject system claims like c_hash, at_hash into the id_token.
 */
public class OpenIDConnectSystemClaimImpl implements ClaimProvider {
    private static final String SHA384 = "SHA-384";
    private static final String SHA512 = "SHA-512";
    private JWSAlgorithm signatureAlgorithm = null;

    @Override
    public Map<String, Object> getAdditionalClaims(OAuthAuthzReqMessageContext authAuthzReqMessageContext, OAuth2AuthorizeRespDTO authorizeRespDTO) throws IdentityOAuth2Exception {
        //First set the signature Algorithm
        setSignatureAlgorithm();

        Map<String, Object> oidcSystemClaims = new HashMap<>();

        String responseType = authAuthzReqMessageContext.getAuthorizationReqDTO().getResponseType();
        String authorizationCode = authorizeRespDTO.getAuthorizationCode();
        String accessToken = authorizeRespDTO.getAccessToken();

        if (isIDTokenSigned() && isAccessTokenHashApplicable(responseType) && isNotBlank(accessToken)) {
            String atHash = getHashValue(accessToken);
            oidcSystemClaims.put(AT_HASH, atHash);
        }

        if (isIDTokenSigned() && isCodeHashApplicable(responseType) && isNotBlank(authorizationCode)) {
            String cHash = getHashValue(authorizationCode);
            oidcSystemClaims.put(C_HASH, cHash);
        }
        return oidcSystemClaims;
    }

    @Override
    public Map<String, Object> getAdditionalClaims(OAuthTokenReqMessageContext tokenReqMessageContext, OAuth2AccessTokenRespDTO tokenRespDTO) throws IdentityOAuth2Exception {
        //First set the signature Algorithm
        setSignatureAlgorithm();

        Map<String, Object> oidcSystemClaims = new HashMap<>();

        String authorizationCode = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getAuthorizationCode();
        String accessToken = tokenRespDTO.getAccessToken();

        if (isIDTokenSigned() && isNotBlank(accessToken)) {
            String atHash = getHashValue(accessToken);
            oidcSystemClaims.put(AT_HASH, atHash);
        }
        if (isIDTokenSigned() && isNotBlank(authorizationCode)) {
            String cHash = getHashValue(authorizationCode);
            oidcSystemClaims.put(C_HASH, cHash);
        }
        return oidcSystemClaims;
    }

    private void setSignatureAlgorithm() throws IdentityOAuth2Exception {
        signatureAlgorithm = OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(
                OAuthServerConfiguration.getInstance().getIdTokenSignatureAlgorithm());
    }

    private boolean isIDTokenSigned() {
        return !JWSAlgorithm.NONE.getName().equals(signatureAlgorithm.getName());
    }


    /**
     * This returns the base64url encoding of the left-most half of the hash of the octets of the ASCII representation
     * of the param value.
     * The hash algorithm used is the hash algorithm used in the alg Header Parameter of the ID Token's JOSE Header.
     * This method generate both c_hash and at_hash values when value is given as authorization code and access token
     * respectively.
     * @param value
     * @return at_hash or c_hash value
     * @throws IdentityOAuth2Exception
     */
    private String getHashValue(String value) throws IdentityOAuth2Exception {
        String digAlg = OAuth2Util.mapDigestAlgorithm(signatureAlgorithm);
        MessageDigest md;
        try {
            md = MessageDigest.getInstance(digAlg);
        } catch (NoSuchAlgorithmException e) {
            throw new IdentityOAuth2Exception("Error creating the hash value. Invalid Digest Algorithm: " + digAlg);
        }

        md.update(value.getBytes(Charsets.UTF_8));
        byte[] digest = md.digest();
        int leftHalfBytes = 16;
        if (SHA384.equals(digAlg)) {
            leftHalfBytes = 24;
        } else if (SHA512.equals(digAlg)) {
            leftHalfBytes = 32;
        }
        byte[] leftmost = new byte[leftHalfBytes];
        System.arraycopy(digest, 0, leftmost, 0, leftHalfBytes);
        return new String(Base64.encodeBase64URLSafe(leftmost), Charsets.UTF_8);
    }

    private boolean isCodeHashApplicable(String responseType) {
        // If the ID Token is issued from the Authorization Endpoint with a code c_hash should be generated.
        return responseType.contains(ResponseType.CODE.toString()) &&
                !OAuthConstants.NONE.equalsIgnoreCase(responseType);
    }

    private boolean isAccessTokenHashApplicable(String responseType) {
        // At_hash is generated on an access token. Therefore check whether the response type returns an access_token.
        // id_token and none response types don't return and access token
        return !OAuthConstants.ID_TOKEN.equalsIgnoreCase(responseType) &&
                !OAuthConstants.NONE.equalsIgnoreCase(responseType);
    }
}
