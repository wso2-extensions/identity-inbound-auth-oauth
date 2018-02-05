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

import org.apache.commons.logging.LogFactory;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.Test;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.core.internal.CarbonCoreDataHolder;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.core.util.CryptoUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import org.wso2.carbon.registry.core.service.RegistryService;

import java.nio.charset.StandardCharsets;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;

/**
 * Test Class for the EncryptionDecryptionPersistenceProcessor.
 */
@PrepareForTest({
        CryptoUtil.class,
        LogFactory.class,
        CarbonCoreDataHolder.class
})
public class EncryptionDecryptionPersistenceProcessorTest extends PowerMockIdentityBaseTest {

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

        mockStatic(CryptoUtil.class);
        CryptoUtil cryptoUtil = mock(CryptoUtil.class);
        byte[] testbyte = "test".getBytes(StandardCharsets.UTF_8);
        when(cryptoUtil.base64DecodeAndDecrypt(anyString())).thenReturn(testbyte);
        when(CryptoUtil.getDefaultCryptoUtil(any(ServerConfigurationService.class),
                any(RegistryService.class))).thenReturn(cryptoUtil);
        when(CryptoUtil.getDefaultCryptoUtil()).thenReturn(cryptoUtil);

        assertEquals(testclass.getPreprocessedClientSecret("test"), "test");
        assertEquals(testclass.getPreprocessedAuthzCode("test"), "test");
        assertEquals(testclass.getPreprocessedRefreshToken("test"), "test");
        assertEquals(testclass.getPreprocessedAccessTokenIdentifier("test"), "test");
    }

    @Test
    public void testGetProcessed() throws CryptoException, IdentityOAuth2Exception {

        mockStatic(CryptoUtil.class);
        CryptoUtil cryptoUtil = mock(CryptoUtil.class);
        when(cryptoUtil.encryptAndBase64Encode(any(byte[].class))).thenReturn("test");
        when(CryptoUtil.getDefaultCryptoUtil(any(ServerConfigurationService.class),
                any(RegistryService.class))).thenReturn(cryptoUtil);
        when(CryptoUtil.getDefaultCryptoUtil()).thenReturn(cryptoUtil);

        assertEquals(testclass.getProcessedClientSecret("test"), "test");
        assertEquals(testclass.getProcessedAuthzCode("test"), "test");
        assertEquals(testclass.getProcessedRefreshToken("test"), "test");
        assertEquals(testclass.getProcessedAccessTokenIdentifier("test"), "test");
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testIdentityOAuth2ExceptionForGetPreprocessedAuthzCode()
            throws CryptoException, IdentityOAuth2Exception {

        mockStatic(CryptoUtil.class);
        CryptoUtil cryptoUtil = mock(CryptoUtil.class);
        when(cryptoUtil.base64DecodeAndDecrypt(anyString())).thenThrow(new CryptoException());
        when(CryptoUtil.getDefaultCryptoUtil(any(ServerConfigurationService.class),
                any(RegistryService.class))).thenReturn(cryptoUtil);
        when(CryptoUtil.getDefaultCryptoUtil()).thenReturn(cryptoUtil);
        testclass.getPreprocessedAuthzCode("test");
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testIdentityOAuth2ExceptionForGetPreprocessedAccessTokenIdentifier()
            throws CryptoException, IdentityOAuth2Exception {

        mockStatic(CryptoUtil.class);
        CryptoUtil cryptoUtil = mock(CryptoUtil.class);
        when(cryptoUtil.base64DecodeAndDecrypt(anyString())).thenThrow(new CryptoException());
        when(CryptoUtil.getDefaultCryptoUtil(any(ServerConfigurationService.class),
                any(RegistryService.class))).thenReturn(cryptoUtil);
        when(CryptoUtil.getDefaultCryptoUtil()).thenReturn(cryptoUtil);
        testclass.getPreprocessedAccessTokenIdentifier("test");
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testIdentityOAuth2ExceptionForGetPreprocessedRefreshToken()
            throws CryptoException, IdentityOAuth2Exception {

        mockStatic(CryptoUtil.class);
        CryptoUtil cryptoUtil = mock(CryptoUtil.class);
        when(cryptoUtil.base64DecodeAndDecrypt(anyString())).thenThrow(new CryptoException());
        when(CryptoUtil.getDefaultCryptoUtil(any(ServerConfigurationService.class),
                any(RegistryService.class))).thenReturn(cryptoUtil);
        when(CryptoUtil.getDefaultCryptoUtil()).thenReturn(cryptoUtil);
        testclass.getPreprocessedRefreshToken("test");
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testIdentityOAuth2ExceptionForGetPreprocessedClientSecret()
            throws CryptoException, IdentityOAuth2Exception {

        mockStatic(CryptoUtil.class);
        CryptoUtil cryptoUtil = mock(CryptoUtil.class);
        when(cryptoUtil.base64DecodeAndDecrypt(anyString())).thenThrow(new CryptoException());
        when(CryptoUtil.getDefaultCryptoUtil(any(ServerConfigurationService.class),
                any(RegistryService.class))).thenReturn(cryptoUtil);
        when(CryptoUtil.getDefaultCryptoUtil()).thenReturn(cryptoUtil);
        testclass.getPreprocessedClientSecret("test");
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testIdentityOAuth2ExceptionForGetProcessedAuthzCode() throws CryptoException, IdentityOAuth2Exception {

        mockStatic(CryptoUtil.class);
        CryptoUtil cryptoUtil = mock(CryptoUtil.class);
        when(cryptoUtil.encryptAndBase64Encode(any(byte[].class))).thenThrow(new CryptoException());
        when(CryptoUtil.getDefaultCryptoUtil(any(ServerConfigurationService.class),
                any(RegistryService.class))).thenReturn(cryptoUtil);
        when(CryptoUtil.getDefaultCryptoUtil()).thenReturn(cryptoUtil);
        testclass.getProcessedAuthzCode("test");
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testIdentityOAuth2ExceptionForGetProcessedAccessTokenIdentifier()
            throws CryptoException, IdentityOAuth2Exception {

        mockStatic(CryptoUtil.class);
        CryptoUtil cryptoUtil = mock(CryptoUtil.class);
        when(cryptoUtil.encryptAndBase64Encode(any(byte[].class))).thenThrow(new CryptoException());
        when(CryptoUtil.getDefaultCryptoUtil(any(ServerConfigurationService.class),
                any(RegistryService.class))).thenReturn(cryptoUtil);
        when(CryptoUtil.getDefaultCryptoUtil()).thenReturn(cryptoUtil);
        testclass.getProcessedAccessTokenIdentifier("test");
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testIdentityOAuth2ExceptionForGetProcessedRefreshToken()
            throws CryptoException, IdentityOAuth2Exception {

        mockStatic(CryptoUtil.class);
        CryptoUtil cryptoUtil = mock(CryptoUtil.class);
        when(cryptoUtil.encryptAndBase64Encode(any(byte[].class))).thenThrow(new CryptoException());
        when(CryptoUtil.getDefaultCryptoUtil(any(ServerConfigurationService.class),
                any(RegistryService.class))).thenReturn(cryptoUtil);
        when(CryptoUtil.getDefaultCryptoUtil()).thenReturn(cryptoUtil);
        testclass.getProcessedRefreshToken("test");
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testIdentityOAuth2ExceptionForProcessedClientSecret()
            throws CryptoException, IdentityOAuth2Exception {

        mockStatic(CryptoUtil.class);
        CryptoUtil cryptoUtil = mock(CryptoUtil.class);
        when(cryptoUtil.encryptAndBase64Encode(any(byte[].class))).thenThrow(new CryptoException());
        when(CryptoUtil.getDefaultCryptoUtil(any(ServerConfigurationService.class),
                any(RegistryService.class))).thenReturn(cryptoUtil);
        when(CryptoUtil.getDefaultCryptoUtil()).thenReturn(cryptoUtil);
        testclass.getProcessedClientSecret("test");
    }

}
