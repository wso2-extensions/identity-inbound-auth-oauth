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

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.central.log.mgt.internal.CentralLogMgtServiceComponentHolder;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.getKeyStoreFromFile;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.getRequestObjects;

@Listeners(MockitoTestNGListener.class)
public class RequestParamRequestObjectBuilderTest {

    private RSAPrivateKey rsaPrivateKey;
    private KeyStore clientKeyStore;
    private KeyStore wso2KeyStore;
    public static final String TEST_CLIENT_ID_1 = "wso2test";
    public static final String SOME_SERVER_URL = "some-server-url";

    @Mock
    private CentralLogMgtServiceComponentHolder centralLogMgtServiceComponentHolderMock;

    @BeforeClass
    public void setUp() throws Exception {

        System.setProperty(CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString());
        clientKeyStore = getKeyStoreFromFile("testkeystore.jks", "wso2carbon",
                System.getProperty(CarbonBaseConstants.CARBON_HOME));
        wso2KeyStore = getKeyStoreFromFile("wso2carbon.jks", "wso2carbon", System.getProperty(CarbonBaseConstants
                .CARBON_HOME));
    }

    @DataProvider(name = "TestBuildRequestObjectTest")
    public Object[][] buildRequestObjectData() throws Exception {

        Key privateKey = clientKeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
        Key privateKey2 = wso2KeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
        PublicKey publicKey = wso2KeyStore.getCertificate("wso2carbon").getPublicKey();
        return getRequestObjects(privateKey, privateKey2, publicKey, TEST_CLIENT_ID_1, SOME_SERVER_URL);
    }

    @Test(dataProvider = "TestBuildRequestObjectTest")
    public void buildRequestObjectTest(String requestObjectString, Map<String, Object> claims, boolean isSigned,
                                       boolean isEncrypted,
                                       boolean exceptionNotExpected,
                                       String errorMsg, boolean isFAPITest, String encryptionAlgo,
                                       String encryptionMethod) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class)) {
            OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(oauthServerConfigurationMock);

            try (MockedStatic<LoggerUtils> loggerUtils = mockStatic(LoggerUtils.class);
                 MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<CentralLogMgtServiceComponentHolder> centralLogMgtServiceComponentHolder =
                         mockStatic(CentralLogMgtServiceComponentHolder.class);
                 MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {
                loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
                IdentityEventService eventServiceMock = mock(IdentityEventService.class);
                centralLogMgtServiceComponentHolder.when(CentralLogMgtServiceComponentHolder::getInstance)
                        .thenReturn(centralLogMgtServiceComponentHolderMock);
                lenient().when(centralLogMgtServiceComponentHolderMock.getIdentityEventService())
                        .thenReturn(eventServiceMock);
                lenient().doNothing().when(eventServiceMock).handleEvent(any());
                identityUtil.when(() -> IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean()))
                        .thenReturn("some-server-url");

                OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
                oAuth2Parameters.setTenantDomain("carbon.super");
                oAuth2Parameters.setClientId(TEST_CLIENT_ID_1);

//        MockedStatic<RequestObjectValidatorImpl> requestObjectValidator =
//                mockStatic(RequestObjectValidatorImpl.class);
//        spy(RequestObjectValidatorImpl.class);

                rsaPrivateKey = (RSAPrivateKey) wso2KeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
                oAuth2Util.when(() -> OAuth2Util.getTenantId("carbon.super")).thenReturn(-1234);
                oAuth2Util.when(() -> OAuth2Util.getPrivateKey(anyString(), anyInt())).thenReturn(rsaPrivateKey);
                oAuth2Util.when(() -> OAuth2Util.getX509CertOfOAuthApp(TEST_CLIENT_ID_1,
                                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME))
                        .thenReturn(clientKeyStore.getCertificate("wso2carbon"));

                OAuthAppDO oAuthAppDO = new OAuthAppDO();
                oAuthAppDO.setRequestObjectEncryptionMethod(encryptionMethod);
                oAuthAppDO.setRequestObjectEncryptionAlgorithm(encryptionAlgo);
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString(), anyString()))
                        .thenReturn(oAuthAppDO);

                RequestObjectValidator requestObjectValidator = new RequestObjectValidatorImpl();
                lenient().when((oauthServerConfigurationMock.getRequestObjectValidator()))
                        .thenReturn(requestObjectValidator);

                RequestObject requestObject;
                RequestParamRequestObjectBuilder requestParamRequestObjectBuilder =
                        new RequestParamRequestObjectBuilder();

                try {
                    requestObject =
                            requestParamRequestObjectBuilder.buildRequestObject(requestObjectString, oAuth2Parameters);
                    Assert.assertEquals(requestObject.isSigned(), isSigned, errorMsg);
                    if (claims != null && !claims.isEmpty()) {
                        for (Map.Entry<String, Object> entry : claims.entrySet()) {
                            if ("nbf".equals(entry.getKey()) || "exp".equals(entry.getKey())) {
                                Assert.assertEquals(((Date) requestObject.getClaim(entry.getKey())).getTime() / 1000,
                                        entry.getValue(), "Request object claim:" + entry.getKey() +
                                                " is not properly set.");
                            } else {
                                Assert.assertEquals(requestObject.getClaim(entry.getKey()), entry.getValue(),
                                        "Request object claim:" + entry.getKey() + " is not properly set.");
                            }
                        }
                    }
                } catch (RequestObjectException e) {
                    Assert.assertFalse(exceptionNotExpected, errorMsg + " Building failed due to " + e.getMessage());
                }
            }
        }
    }
}
