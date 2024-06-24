/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.par.core;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.par.dao.ParDAOFactory;
import org.wso2.carbon.identity.oauth.par.dao.ParMgtDAO;
import org.wso2.carbon.identity.oauth.par.exceptions.ParClientException;
import org.wso2.carbon.identity.oauth.par.exceptions.ParCoreException;
import org.wso2.carbon.identity.oauth.par.model.ParAuthData;
import org.wso2.carbon.identity.oauth.par.model.ParRequestDO;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * Test class for ParAuthService.
 */
public class ParAuthServiceTest {

    @Mock
    ParMgtDAO parMgtDAO;
    @Mock
    ParDAOFactory mockParDAOFactory;
    @Mock
    IdentityConfigParser mockIdentityConfigParser;
    @Mock
    ParRequestDO parRequestDO;

    private static final String UUID = "c0143cb3-7ae0-43a3-a023b7218c7182df";
    private static final String CLIENT_ID_VALUE = "ca19a540f544777860e44e75f605d927";
    private ParAuthServiceImpl parAuthService;

    private MockedStatic<LoggerUtils> loggerUtils;
    private MockedStatic<ParDAOFactory> parDAOFactory;

    @BeforeMethod
    public void setUp() throws Exception {

        initMocks(this);
        loggerUtils = mockStatic(LoggerUtils.class);
        loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
        parAuthService = new ParAuthServiceImpl();
        parDAOFactory = mockStatic(ParDAOFactory.class);
        parDAOFactory.when(ParDAOFactory::getInstance).thenReturn(mockParDAOFactory);
        when(mockParDAOFactory.getParAuthMgtDAO()).thenReturn(parMgtDAO);
        Field field = ParAuthServiceImpl.class.getDeclaredField("parMgtDAO");
        field.setAccessible(true);
        field.set(parAuthService, ParDAOFactory.getInstance().getParAuthMgtDAO());
    }

    @AfterMethod
    public void tearDown() {

        loggerUtils.close();
        parDAOFactory.close();
    }

    @DataProvider(name = "provideExpiryTimeConfigData")
    public Object[][] provideExpiryTimeConfigData() {

        return new Object[][]{
                // invalid negative number
                {"-1"},
                // invalid zero
                {"0"},
                // valid positive integer
                {"60"},
                // no config value
                {null}
        };
    }

    @Test(dataProvider = "provideExpiryTimeConfigData")
    public void testExpiryTimeConfig(String expiryTime) throws ParCoreException {

        try (MockedStatic<IdentityConfigParser> identityConfigParser = mockStatic(IdentityConfigParser.class)) {
            doNothing().when(parMgtDAO).persistRequestData(anyString(), anyString(), anyLong(), anyMap());
            identityConfigParser.when(IdentityConfigParser::getInstance).thenReturn(mockIdentityConfigParser);
            when(mockIdentityConfigParser.getConfiguration()).thenReturn(
                    new HashMap<String, Object>() {
                        {
                            put("OAuth.PAR.ExpiryTime", expiryTime);
                        }
                    });
            ParAuthData parAuthData = parAuthService.handleParAuthRequest(new HashMap<>());
            assertNotNull(parAuthData.getrequestURIReference());
            long defaultExpiry = 60L;
            assertEquals(parAuthData.getExpiryTime(), defaultExpiry);
        }
    }

    @DataProvider(name = "provideNotANumberExpiryTimeConfigData")
    public Object[][] provideNotANumberExpiryTimeConfigData() {

        return new Object[][]{
                // invalid string
                {"NaN"},
                // invalid decimal
                {"50.45"}
        };
    }

    @Test(dataProvider = "provideNotANumberExpiryTimeConfigData")
    public void testNotANumberExpiryTimeFailure(String expiryTime) throws ParCoreException {

        try (MockedStatic<IdentityConfigParser> identityConfigParser = mockStatic(IdentityConfigParser.class)) {
            doNothing().when(parMgtDAO).persistRequestData(anyString(), anyString(), anyLong(), anyMap());
            identityConfigParser.when(IdentityConfigParser::getInstance).thenReturn(mockIdentityConfigParser);
            Map<String, Object> config = new HashMap<>();
            config.put("OAuth.PAR.ExpiryTime", expiryTime);
            when(mockIdentityConfigParser.getConfiguration()).thenReturn(config);

            try {
                parAuthService.handleParAuthRequest(new HashMap<>());
            } catch (ParCoreException e) {
                assertEquals(e.getMessage(), "Error while parsing the expiry time value.");
            }
        }
    }

    @DataProvider(name = "provideRetrieveParamsData")
    public Object[][] provideRetrieveParamsData() {

        return new Object[][]{
                // Expired request uri
                {System.currentTimeMillis() - 5, CLIENT_ID_VALUE,
                        OAuth2ErrorCodes.OAuth2SubErrorCodes.INVALID_REQUEST_URI},
                // Mismatching client ids
                {System.currentTimeMillis() + 60, "ga39a580f545777860e44e75b605d920", OAuth2ErrorCodes.INVALID_REQUEST}
        };
    }

    @Test(dataProvider = "provideRetrieveParamsData")
    public void testRetrieveParamsFailure(long expiryTime, String clientId, String expectedError)
            throws ParCoreException {

        when(parMgtDAO.getRequestData(anyString())).thenReturn(Optional.ofNullable(parRequestDO));
        when(parRequestDO.getExpiresIn()).thenReturn(expiryTime);
        when(parRequestDO.getClientId()).thenReturn(clientId);

        try {
            parAuthService.retrieveParams(UUID, CLIENT_ID_VALUE);
        } catch (ParClientException e) {
            assertEquals(e.getErrorCode(), expectedError);
        }
    }
}
