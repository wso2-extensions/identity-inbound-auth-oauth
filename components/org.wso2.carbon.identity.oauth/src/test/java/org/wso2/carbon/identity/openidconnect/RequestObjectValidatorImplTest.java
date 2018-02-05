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

import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;

import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@PrepareForTest({OAuth2Util.class, OAuthServerConfiguration.class, RequestObjectValidatorImpl.class, KeyStoreManager.class})
public class RequestObjectValidatorImplTest extends PowerMockTestCase {
    private RSAPrivateKey rsaPrivateKey;

    @BeforeTest
    public void setUp() throws Exception {
        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString());
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }

    @Test(expectedExceptions = RequestObjectException.class)
    public void validateRequestObjectTest() throws Exception {
        RequestObjectTest requestObjectInstance = new RequestObjectTest();
        String requestObject = requestObjectInstance.getEncodeRequestObject();
        RequestObjectValidator requestObjectValidator = new RequestObjectValidatorImpl();
        OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
        oAuth2Parameters.setTenantDomain("carbon.super");
        OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oauthServerConfigurationMock);

        mockStatic(OAuth2Util.class);
        when(OAuth2Util.isValidJson(requestObject)).thenReturn(false);

        mockStatic(RequestObjectValidatorImpl.class);
        PowerMockito.spy(RequestObjectValidatorImpl.class);
        Path clientStorePath = Paths.get(System.getProperty(CarbonBaseConstants.CARBON_HOME), "repository", "resources",
                "security", "client-truststore.jks");
        Path configPath = Paths.get(System.getProperty(CarbonBaseConstants.CARBON_HOME), "repository", "conf",
                "identity", "EndpointConfig.properties");

        PowerMockito.doReturn(configPath.toString()).when(RequestObjectValidatorImpl.class, "buildFilePath",
                "./repository/conf/identity/EndpointConfig.properties");
        PowerMockito.doReturn(clientStorePath.toString()).when(RequestObjectValidatorImpl.class, "buildFilePath",
                "./repository/resources/security/client-truststore.jks");
        requestObjectValidator.validateRequestObject(requestObject, oAuth2Parameters);
        Assert.assertNotNull(requestObjectValidator.getPayload(), "Payload should not a null value.");
    }

    @Test(expectedExceptions = RequestObjectException.class)
    public void DecryptTest() throws Exception {
        RequestObjectTest requestObjectInstance = new RequestObjectTest();
        String requestObject = requestObjectInstance.getEncryptedRequestObject();
        RequestObjectValidator requestObjectValidator = new RequestObjectValidatorImpl();
        OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
        oAuth2Parameters.setTenantDomain("carbon.super");

        OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
        rsaPrivateKey = Mockito.mock(RSAPrivateKey.class);
        PrivateKey privateKey = mock(PrivateKey.class);

        KeyStoreManager keyStoreManagerMock = mock(KeyStoreManager.class);
        when(keyStoreManagerMock.getDefaultPrivateKey()).thenReturn(privateKey);

        mockStatic(KeyStoreManager.class);
        when(KeyStoreManager.getInstance(-1234)).thenReturn(keyStoreManagerMock);

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oauthServerConfigurationMock);

        mockStatic(OAuth2Util.class);
        when(OAuth2Util.isValidJson(requestObject)).thenReturn(false);
        when(OAuth2Util.getTenantId("carbon.super")).thenReturn(-1234);
        when((OAuth2Util.getPrivateKey(anyString(), anyInt()))).thenReturn(rsaPrivateKey);

        requestObjectValidator.validateRequestObject(requestObject, oAuth2Parameters);
        Assert.assertNotNull(requestObjectValidator.getPayload(), "Failed to decrypt the request object.");

    }
}
