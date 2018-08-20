/*
 *
 *   Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 * /
 */
package org.wso2.carbon.identity.oauth.tokenprocessor;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.json.JSONObject;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * An implementation of <Code>TokenPersistenceProcessor</Code>
 * which is used when storing hashed tokens and authorization codes.
 */
public class HashingPersistenceProcessor implements TokenPersistenceProcessor {

    protected Log log = LogFactory.getLog(HashingPersistenceProcessor.class);
    public static final String ALGORITHM = "algorithm";
    public static final String HASH = "hash";

    @Override
    public String getProcessedClientId(String clientId) throws IdentityOAuth2Exception {

        return clientId;
    }

    @Override
    public String getPreprocessedClientId(String processedClientId) throws IdentityOAuth2Exception {

        return processedClientId;
    }

    @Override
    public String getProcessedClientSecret(String clientSecret) throws IdentityOAuth2Exception {

        return hash(clientSecret);
    }

    @Override
    public String getPreprocessedClientSecret(String processedClientSecret) throws IdentityOAuth2Exception {

        throw new UnsupportedOperationException("Invalid operation on hashed client secret");
    }

    @Override
    public String getProcessedAuthzCode(String authzCode) throws IdentityOAuth2Exception {

        return hash(authzCode);
    }

    @Override
    public String getPreprocessedAuthzCode(String processedAuthzCode) throws IdentityOAuth2Exception {

        throw new UnsupportedOperationException("Invalid operation on hashed authorization code");
    }

    @Override
    public String getProcessedAccessTokenIdentifier(String accessTokenIdentifier) throws IdentityOAuth2Exception {

        return hash(accessTokenIdentifier);
    }

    @Override
    public String getPreprocessedAccessTokenIdentifier(String processedAccessTokenIdentifier)
            throws IdentityOAuth2Exception {

        throw new UnsupportedOperationException("Invalid operation on hashed access token");
    }

    @Override
    public String getProcessedRefreshToken(String refreshToken) throws IdentityOAuth2Exception {

        return hash(refreshToken);
    }

    @Override
    public String getPreprocessedRefreshToken(String processedRefreshToken) throws IdentityOAuth2Exception {

        throw new UnsupportedOperationException("Invalid operation on hashed refresh token");
    }

    /**
     * Method to generate hash value
     *
     * @param plainText
     * @return hashed value
     */
    private String hash(String plainText) throws IdentityOAuth2Exception {

        if (StringUtils.isEmpty(plainText)) {
            throw new IdentityOAuth2Exception("plainText value is null or empty to be hash.");
        }

        MessageDigest messageDigest = null;
        byte[] hash = null;
        String hashAlgorithm = OAuthServerConfiguration.getInstance().getHashAlgorithm();
        try {
            messageDigest = MessageDigest.getInstance(hashAlgorithm);
            messageDigest.update(plainText.getBytes());
            hash = messageDigest.digest();

        } catch (NoSuchAlgorithmException e) {
            throw new IdentityOAuth2Exception(
                    "Error while retrieving MessageDigest for the provided hash algorithm: " + hashAlgorithm, e);
        }
        JSONObject object = new JSONObject();
        object.put(ALGORITHM, hashAlgorithm);
        object.put(HASH, bytesToHex(hash));
        return object.toString();
    }

    private static String bytesToHex(byte[] bytes) {

        StringBuilder result = new StringBuilder();
        for (byte byt : bytes) {
            result.append(Integer.toString((byt & 0xff) + 0x100, 16).substring(1));
        }
        return result.toString();
    }
}
