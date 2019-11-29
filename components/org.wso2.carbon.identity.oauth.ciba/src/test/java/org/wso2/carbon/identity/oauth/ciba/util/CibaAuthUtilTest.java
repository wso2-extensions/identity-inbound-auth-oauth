/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.ciba.util;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthResponseDTO;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

/**
 * Unit tests for OAuthUtil class.
 */
@PrepareForTest({OAuth2Util.class, OAuthServerConfiguration .class})
public class CibaAuthUtilTest extends PowerMockTestCase {

    private static final long EXPIRES_IN_DEFAULT_VALUE_IN_SEC = 3600;
    private static final long MAXIMUM_REQUESTED_EXPIRY_IN_SEC = 3600;
    private static final String CONSUMER_KEY = "ZzxmDqqK8YYfjtlOh9vw85qnNVoa";
    private static final String DEFAULT_CALLBACK_URL = "https://localhost/CibaResponse";
    private static final String AUTH_REQ_ID = "2201e5aa-1c5f-4a17-90c9-1956a3540b19";
    private static final String AUTH_CODE_KEY = "47457g3w-1c5f-5erd-rd43-1952a3540b7";
    private static final String USER_HINT = "RandomUser";

    @Mock
    OAuthServerConfiguration oAuthServerConfiguration;

    @BeforeMethod

    public void setUp() throws Exception {
        mockStatic(OAuthServerConfiguration .class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
    }

    @DataProvider(name = "provideRequestedExpiryData")
    public Object[][] provideRequestedExpiryData() {

        CibaAuthRequestDTO cibaAuthRequestDTOEmpty = new CibaAuthRequestDTO();

        CibaAuthRequestDTO cibaAuthRequestDTOLessVal = new CibaAuthRequestDTO();
        cibaAuthRequestDTOLessVal.setRequestedExpiry(120L);

        CibaAuthRequestDTO cibaAuthRequestDTOHighVal = new CibaAuthRequestDTO();
        cibaAuthRequestDTOHighVal.setIssuer(CONSUMER_KEY);
        cibaAuthRequestDTOHighVal.setRequestedExpiry(5000L);

        CibaAuthRequestDTO cibaAuthRequestDTOZero = new CibaAuthRequestDTO();
        cibaAuthRequestDTOZero.setRequestedExpiry(0);

        return new Object[][]{
                {cibaAuthRequestDTOEmpty, EXPIRES_IN_DEFAULT_VALUE_IN_SEC},
                {cibaAuthRequestDTOLessVal, 120L},
                {cibaAuthRequestDTOHighVal, MAXIMUM_REQUESTED_EXPIRY_IN_SEC},
                {cibaAuthRequestDTOZero, EXPIRES_IN_DEFAULT_VALUE_IN_SEC},

        };
    }

    @Test(dataProvider = "provideRequestedExpiryData")
    public void testExpiresIn(Object cibaAuthResponseDTOObject, long expected) throws Exception {

        CibaAuthRequestDTO cibaAuthRequestDTO = (CibaAuthRequestDTO) cibaAuthResponseDTOObject;

        Assert.assertEquals(expected, CibaAuthUtil.getExpiresIn(cibaAuthRequestDTO));
    }

    @DataProvider(name = "provideRequestedResponseData")
    public Object[][] provideRequestedResponseData() {

        CibaAuthRequestDTO cibaAuthRequestDTO = new CibaAuthRequestDTO();
        cibaAuthRequestDTO.setRequestedExpiry(0);
        cibaAuthRequestDTO.setIssuer(CONSUMER_KEY);

        String[] scope = new String[]{"openid", "phone", "sms"};

        cibaAuthRequestDTO.setScope(scope);

        return new Object[][]{
                {cibaAuthRequestDTO},
        };
    }

    @Test(dataProvider = "provideRequestedResponseData")
    public void testGenerateCibaAuthCodeDO(Object cibaAuthResponseDTOObject) throws Exception {

        CibaAuthRequestDTO cibaAuthRequestDTO = (CibaAuthRequestDTO) cibaAuthResponseDTOObject;

        Assert.assertEquals("REQUESTED",
                CibaAuthUtil.generateCibaAuthCodeDO(cibaAuthRequestDTO).getAuthenticationStatus().toString());
        Assert.assertEquals(2L, CibaAuthUtil.generateCibaAuthCodeDO(cibaAuthRequestDTO).getInterval());

        Assert.assertEquals(EXPIRES_IN_DEFAULT_VALUE_IN_SEC,
                CibaAuthUtil.generateCibaAuthCodeDO(cibaAuthRequestDTO).getExpiresIn());

        Assert.assertEquals(CONSUMER_KEY, CibaAuthUtil.generateCibaAuthCodeDO(cibaAuthRequestDTO).getConsumerAppKey());

        Assert.assertNotNull(CibaAuthUtil.generateCibaAuthCodeDO(cibaAuthRequestDTO).getAuthReqID());
        Assert.assertNotNull(CibaAuthUtil.generateCibaAuthCodeDO(cibaAuthRequestDTO).getCibaAuthCodeKey());
        Assert.assertNotNull(CibaAuthUtil.generateCibaAuthCodeDO(cibaAuthRequestDTO).getScope());
    }

    @DataProvider(name = "provideRequestedAuthzData")
    public Object[][] provideRequestedAuthzData() {

        String bindingMessage = "randomBinding";

        CibaAuthRequestDTO cibaAuthRequestDTO = new CibaAuthRequestDTO();
        cibaAuthRequestDTO.setUserHint(USER_HINT);
        cibaAuthRequestDTO.setIssuer(CONSUMER_KEY);
        String scope[] = new String[]{"openid", "phone", "sms"};

        CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();
        cibaAuthCodeDO.setConsumerAppKey(CONSUMER_KEY);
        cibaAuthCodeDO.setScope(scope);
        cibaAuthCodeDO.setAuthReqID(AUTH_REQ_ID);
        cibaAuthCodeDO.setCibaAuthCodeKey(AUTH_CODE_KEY);

        CibaAuthRequestDTO cibaAuthRequestDTOWithBind = new CibaAuthRequestDTO();
        cibaAuthRequestDTOWithBind.setUserHint(USER_HINT);
        cibaAuthRequestDTOWithBind.setBindingMessage(bindingMessage);
        cibaAuthRequestDTOWithBind.setIssuer(CONSUMER_KEY);

        return new Object[][]{
                {cibaAuthRequestDTO, cibaAuthCodeDO, null},
                {cibaAuthRequestDTOWithBind, cibaAuthCodeDO, bindingMessage},
        };
    }

    @Test(dataProvider = "provideRequestedAuthzData")
    protected void testBuildAuthzRequestDOForCIBA(Object cibaAuthResponseDTOObject, Object cibaAuthCodeDoObject,
                                                  String bindingMessage) throws Exception {

        CibaAuthRequestDTO cibaAuthRequestDTO = (CibaAuthRequestDTO) cibaAuthResponseDTOObject;
        CibaAuthCodeDO cibaAuthCodeDO = (CibaAuthCodeDO) cibaAuthCodeDoObject;

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setCallbackUrl(DEFAULT_CALLBACK_URL);

        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(appDO);

        CibaAuthResponseDTO cibaAuthResponseDTO = CibaAuthUtil.buildAuthResponseDTO(cibaAuthRequestDTO, cibaAuthCodeDO);

        Assert.assertEquals(USER_HINT, cibaAuthResponseDTO.getUserHint());
        Assert.assertEquals(CONSUMER_KEY, cibaAuthResponseDTO.getClientId());
        Assert.assertEquals(DEFAULT_CALLBACK_URL, cibaAuthResponseDTO.getCallBackUrl());
        Assert.assertEquals(bindingMessage, cibaAuthResponseDTO.getBindingMessage());
        Assert.assertEquals(AUTH_REQ_ID, cibaAuthResponseDTO.getAuthReqId());
    }
}
