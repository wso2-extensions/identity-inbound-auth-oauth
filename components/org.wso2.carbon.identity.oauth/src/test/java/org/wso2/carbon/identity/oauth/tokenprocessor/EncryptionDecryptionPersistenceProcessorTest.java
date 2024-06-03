/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.mockito.MockedStatic;
import org.testng.annotations.Test;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.core.util.CryptoUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.registry.core.service.RegistryService;

import java.nio.charset.StandardCharsets;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

/**
 * Test Class for the EncryptionDecryptionPersistenceProcessor.
 */
public class EncryptionDecryptionPersistenceProcessorTest {

    private EncryptionDecryptionPersistenceProcessor testclass = new EncryptionDecryptionPersistenceProcessor();

    @Test
    public void testGetPreprocessedClientId() throws IdentityOAuth2Exception {

        assertEquals(testclass.getPreprocessedClientId("testPreId"), "testPreId");
    }

    @Test
    public void testGetProcessedClientId() throws Exception {

        assertEquals(testclass.getProcessedClientId("testId"), "testId");
    }

    @Test
    public void testGetPreprocessed() throws CryptoException, IdentityOAuth2Exception {

        try (MockedStatic<CryptoUtil> cryptoUtil = mockStatic(CryptoUtil.class)) {
            CryptoUtil mockCryptoUtil = mock(CryptoUtil.class);
            byte[] testbyte = "test".getBytes(StandardCharsets.UTF_8);
            when(mockCryptoUtil.base64DecodeAndDecrypt(anyString())).thenReturn(testbyte);
            cryptoUtil.when(() -> CryptoUtil.getDefaultCryptoUtil(any(ServerConfigurationService.class),
                    any(RegistryService.class))).thenReturn(mockCryptoUtil);
            cryptoUtil.when(CryptoUtil::getDefaultCryptoUtil).thenReturn(mockCryptoUtil);

            assertEquals(testclass.getPreprocessedClientSecret("test"), "test");
            assertEquals(testclass.getPreprocessedAuthzCode("test"), "test");
            assertEquals(testclass.getPreprocessedRefreshToken("test"), "test");
            assertEquals(testclass.getPreprocessedAccessTokenIdentifier("test"), "test");
        }
    }

    @Test
    public void testGetProcessed() throws CryptoException, IdentityOAuth2Exception {

        try (MockedStatic<CryptoUtil> cryptoUtil = mockStatic(CryptoUtil.class)) {
            CryptoUtil mockCryptoUtil = mock(CryptoUtil.class);
            when(mockCryptoUtil.encryptAndBase64Encode(any(byte[].class))).thenReturn("test");
            cryptoUtil.when(() -> CryptoUtil.getDefaultCryptoUtil(any(ServerConfigurationService.class),
                    any(RegistryService.class))).thenReturn(mockCryptoUtil);
            cryptoUtil.when(CryptoUtil::getDefaultCryptoUtil).thenReturn(mockCryptoUtil);

            assertEquals(testclass.getProcessedClientSecret("test"), "test");
            assertEquals(testclass.getProcessedAuthzCode("test"), "test");
            assertEquals(testclass.getProcessedRefreshToken("test"), "test");
            assertEquals(testclass.getProcessedAccessTokenIdentifier("test"), "test");
        }
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testIdentityOAuth2ExceptionForGetPreprocessedAuthzCode()
            throws CryptoException, IdentityOAuth2Exception {

        try (MockedStatic<CryptoUtil> cryptoUtil = mockStatic(CryptoUtil.class)) {
            CryptoUtil mockCryptoUtil = mock(CryptoUtil.class);
            when(mockCryptoUtil.base64DecodeAndDecrypt(anyString())).thenThrow(new CryptoException());
            cryptoUtil.when(() -> CryptoUtil.getDefaultCryptoUtil(any(ServerConfigurationService.class),
                    any(RegistryService.class))).thenReturn(mockCryptoUtil);
            cryptoUtil.when(CryptoUtil::getDefaultCryptoUtil).thenReturn(mockCryptoUtil);
            testclass.getPreprocessedAuthzCode("test");
        }
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testIdentityOAuth2ExceptionForGetPreprocessedAccessTokenIdentifier()
            throws CryptoException, IdentityOAuth2Exception {

        try (MockedStatic<CryptoUtil> cryptoUtil = mockStatic(CryptoUtil.class)) {
            CryptoUtil mockCryptoUtil = mock(CryptoUtil.class);
            when(mockCryptoUtil.base64DecodeAndDecrypt(anyString())).thenThrow(new CryptoException());
            cryptoUtil.when(() -> CryptoUtil.getDefaultCryptoUtil(any(ServerConfigurationService.class),
                    any(RegistryService.class))).thenReturn(mockCryptoUtil);
            cryptoUtil.when(CryptoUtil::getDefaultCryptoUtil).thenReturn(mockCryptoUtil);
            testclass.getPreprocessedAccessTokenIdentifier("test");
        }
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testIdentityOAuth2ExceptionForGetPreprocessedRefreshToken()
            throws CryptoException, IdentityOAuth2Exception {

        try (MockedStatic<CryptoUtil> cryptoUtil = mockStatic(CryptoUtil.class)) {
            CryptoUtil mockCryptoUtil = mock(CryptoUtil.class);
            when(mockCryptoUtil.base64DecodeAndDecrypt(anyString())).thenThrow(new CryptoException());
            cryptoUtil.when(()->CryptoUtil.getDefaultCryptoUtil(any(ServerConfigurationService.class),
                    any(RegistryService.class))).thenReturn(mockCryptoUtil);
            cryptoUtil.when(CryptoUtil::getDefaultCryptoUtil).thenReturn(mockCryptoUtil);
            testclass.getPreprocessedRefreshToken("test");
        }
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testIdentityOAuth2ExceptionForGetPreprocessedClientSecret()
            throws CryptoException, IdentityOAuth2Exception {

        try (MockedStatic<CryptoUtil> cryptoUtil = mockStatic(CryptoUtil.class)) {
            CryptoUtil mockCryptoUtil = mock(CryptoUtil.class);
            when(mockCryptoUtil.base64DecodeAndDecrypt(anyString())).thenThrow(new CryptoException());
            cryptoUtil.when(() -> CryptoUtil.getDefaultCryptoUtil(any(ServerConfigurationService.class),
                    any(RegistryService.class))).thenReturn(mockCryptoUtil);
            cryptoUtil.when(CryptoUtil::getDefaultCryptoUtil).thenReturn(mockCryptoUtil);
            testclass.getPreprocessedClientSecret("test");
        }
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testIdentityOAuth2ExceptionForGetProcessedAuthzCode() throws CryptoException, IdentityOAuth2Exception {

        try (MockedStatic<CryptoUtil> cryptoUtil = mockStatic(CryptoUtil.class)) {
            CryptoUtil mockCryptoUtil = mock(CryptoUtil.class);
            when(mockCryptoUtil.encryptAndBase64Encode(any(byte[].class))).thenThrow(new CryptoException());
            cryptoUtil.when(() -> CryptoUtil.getDefaultCryptoUtil(any(ServerConfigurationService.class),
                    any(RegistryService.class))).thenReturn(mockCryptoUtil);
            cryptoUtil.when(CryptoUtil::getDefaultCryptoUtil).thenReturn(mockCryptoUtil);
            testclass.getProcessedAuthzCode("test");
        }
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testIdentityOAuth2ExceptionForGetProcessedAccessTokenIdentifier()
            throws CryptoException, IdentityOAuth2Exception {

        try (MockedStatic<CryptoUtil> cryptoUtil = mockStatic(CryptoUtil.class)) {
            CryptoUtil mockCryptoUtil = mock(CryptoUtil.class);
            when(mockCryptoUtil.encryptAndBase64Encode(any(byte[].class))).thenThrow(new CryptoException());
            cryptoUtil.when(() -> CryptoUtil.getDefaultCryptoUtil(any(ServerConfigurationService.class),
                    any(RegistryService.class))).thenReturn(mockCryptoUtil);
            cryptoUtil.when(CryptoUtil::getDefaultCryptoUtil).thenReturn(mockCryptoUtil);
            testclass.getProcessedAccessTokenIdentifier("test");
        }
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testIdentityOAuth2ExceptionForGetProcessedRefreshToken()
            throws CryptoException, IdentityOAuth2Exception {

        try (MockedStatic<CryptoUtil> cryptoUtil = mockStatic(CryptoUtil.class)) {
            CryptoUtil mockCryptoUtil = mock(CryptoUtil.class);
            when(mockCryptoUtil.encryptAndBase64Encode(any(byte[].class))).thenThrow(new CryptoException());
            cryptoUtil.when(() -> CryptoUtil.getDefaultCryptoUtil(any(ServerConfigurationService.class),
                    any(RegistryService.class))).thenReturn(mockCryptoUtil);
            cryptoUtil.when(CryptoUtil::getDefaultCryptoUtil).thenReturn(mockCryptoUtil);
            testclass.getProcessedRefreshToken("test");
        }
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testIdentityOAuth2ExceptionForProcessedClientSecret()
            throws CryptoException, IdentityOAuth2Exception {

        try (MockedStatic<CryptoUtil> cryptoUtil = mockStatic(CryptoUtil.class)) {
            CryptoUtil mockCryptoUtil = mock(CryptoUtil.class);
            when(mockCryptoUtil.encryptAndBase64Encode(any(byte[].class))).thenThrow(new CryptoException());
            cryptoUtil.when(() -> CryptoUtil.getDefaultCryptoUtil(any(ServerConfigurationService.class),
                    any(RegistryService.class))).thenReturn(mockCryptoUtil);
            cryptoUtil.when(CryptoUtil::getDefaultCryptoUtil).thenReturn(mockCryptoUtil);
            testclass.getProcessedClientSecret("test");
        }
    }

}
