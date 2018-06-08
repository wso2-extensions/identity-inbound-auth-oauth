/*
 *  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.oauth.tokenprocessor;

import org.apache.commons.lang.StringUtils;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;

/**
 * Test Class for the EncryptionDecryptionPersistenceProcessor.
 */
@PrepareForTest({OAuthServerConfiguration.class})
public class HashingPersistenceProcessorTest extends PowerMockIdentityBaseTest {

    private String TEST = "test";

    @Mock
    private OAuthServerConfiguration mockedServerConfig;

    private HashingPersistenceProcessor hashingPersistenceProcessor = new HashingPersistenceProcessor();

    @BeforeClass
    public void setUp() throws Exception {
        initMocks(this);
    }

    @Test
    public void testGetPreprocessedClientId() throws IdentityOAuth2Exception {
        assertEquals(hashingPersistenceProcessor.getPreprocessedClientId(TEST), TEST);
    }

    @Test
    public void testGetProcessedClientId() throws Exception {
        assertEquals(hashingPersistenceProcessor.getProcessedClientId(TEST), TEST);
    }

    @Test(expectedExceptions = UnsupportedOperationException.class)
    public void testPreprocessedAuthzCodeWithException() throws IdentityOAuth2Exception {
        hashingPersistenceProcessor.getPreprocessedAuthzCode(TEST);
    }

    @Test(expectedExceptions = UnsupportedOperationException.class)
    public void testPreprocessedAccessTokenIdentifierWithException() throws IdentityOAuth2Exception {
        hashingPersistenceProcessor.getPreprocessedAccessTokenIdentifier(TEST);
    }

    @Test(expectedExceptions = UnsupportedOperationException.class)
    public void testPreprocessedRefreshTokenWithException() throws IdentityOAuth2Exception {
        hashingPersistenceProcessor.getPreprocessedRefreshToken(TEST);
    }

    @Test(expectedExceptions = UnsupportedOperationException.class)
    public void testPreprocessedClientSecretWithException() throws IdentityOAuth2Exception {
        hashingPersistenceProcessor.getPreprocessedClientSecret(TEST);
    }

    @Test
    public void testGetProcessedClientSecret() throws IdentityOAuth2Exception {
        setupMocksForTest();
        assertEquals(hashingPersistenceProcessor.getProcessedClientSecret(TEST), hash(TEST));
    }

    @Test
    public void testGetProcessedAuthzCode() throws IdentityOAuth2Exception {
        setupMocksForTest();
        assertEquals(hashingPersistenceProcessor.getProcessedAuthzCode(TEST), hash(TEST));
    }

    @Test
    public void testGetProcessedAccessTokenIdentifier() throws IdentityOAuth2Exception {
        setupMocksForTest();
        assertEquals(hashingPersistenceProcessor.getProcessedAccessTokenIdentifier(TEST), hash(TEST));
    }

    @Test
    public void testGetProcessedRefreshToken() throws IdentityOAuth2Exception {
        setupMocksForTest();
        assertEquals(hashingPersistenceProcessor.getProcessedRefreshToken(TEST), hash(TEST));
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testHashWithNullValue() throws IdentityOAuth2Exception {
        setupMocksForTest();
        hashingPersistenceProcessor.getProcessedClientSecret(null);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testHahingWithNotExistingHashAlgorithm() throws IdentityOAuth2Exception {
        setupMocksForTest();
        when(OAuthServerConfiguration.getInstance().getHashAlgorithm()).thenReturn("TestAlgo");
        hash("PlainText");
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testHahingWithEmptyString() throws IdentityOAuth2Exception {
        hash("");
    }

    private void setupMocksForTest() {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        when(OAuthServerConfiguration.getInstance().getHashAlgorithm()).thenReturn("SHA-256");
    }

    /**
     * Method to generate hash value.
     *
     * @param plainText Plain text value.
     * @return Hashed value.
     */
    private String hash(String plainText) throws IdentityOAuth2Exception {

        if (StringUtils.isEmpty(plainText)) {
            throw new IdentityOAuth2Exception("plainText value is null or empty to be hash.");
        }

        MessageDigest messageDigest;
        byte[] hash;
        String hashAlgorithm = OAuthServerConfiguration.getInstance().getHashAlgorithm();
        try {
            messageDigest = MessageDigest.getInstance(hashAlgorithm);
            messageDigest.update(plainText.getBytes());
            hash = messageDigest.digest();

        } catch (NoSuchAlgorithmException e) {
            throw new IdentityOAuth2Exception(
                    "Error while retrieving MessageDigest for the provided hash algorithm: " + hashAlgorithm, e);
        }
        return bytesToHex(hash);
    }

    private static String bytesToHex(byte[] bytes) {

        StringBuilder result = new StringBuilder();
        for (byte byt : bytes) {
            result.append(Integer.toString((byt & 0xff) + 0x100, 16).substring(1));
        }
        return result.toString();
    }
}
