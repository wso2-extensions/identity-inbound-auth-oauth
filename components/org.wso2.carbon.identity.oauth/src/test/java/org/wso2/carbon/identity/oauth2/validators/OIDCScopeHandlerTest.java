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

package org.wso2.carbon.identity.oauth2.validators;

import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.openidconnect.dao.ScopeClaimMappingDAOImpl;
import org.wso2.carbon.identity.organization.management.service.util.Utils;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.file.Paths;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

@WithCarbonHome
@WithRealmService(injectToSingletons = {OAuthComponentServiceHolder.class})
@WithH2Database(files = {"dbScripts/identity.sql"})
public class OIDCScopeHandlerTest {

    private MockedStatic<Utils> utilsStaticMock;
    private OIDCScopeHandler oidcScopeHandler;

    @BeforeClass
    public void setup() throws Exception {

        setFinalField(OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO(), "scopeClaimMappingDAOImpl",
                new ScopeClaimMappingDAOImpl());
        utilsStaticMock = mockStatic(Utils.class);
        utilsStaticMock.when(() -> Utils.isClaimAndOIDCScopeInheritanceEnabled(anyString())).thenReturn(false);
    }

    @BeforeMethod
    public void setUp() throws Exception {

        oidcScopeHandler = new OIDCScopeHandler();
    }

    @AfterClass
    public void tearDown() {

        utilsStaticMock.close();
    }

    @DataProvider(name = "ValidateScopeData")
    public Object[][] validateScopeData() {
        return new Object[][]{
                // grantType
                {GrantType.AUTHORIZATION_CODE.toString()},
                {"testGrantType"},
                {"idTokenNotAllowedGrantType"}
        };
    }

    @Test(dataProvider = "ValidateScopeData")
    public void testValidateScope(String grantType) throws Exception {
        String[] scopeArray = new String[]{"scope1", "scope2", "scope3"};
        OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO = new OAuth2TokenValidationRequestDTO();
        OAuth2TokenValidationRequestDTO.OAuth2AccessToken accessToken = oAuth2TokenValidationRequestDTO.new
                OAuth2AccessToken();
        accessToken.setIdentifier("testAccessToken");
        accessToken.setTokenType("bearer");
        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        oAuth2AccessTokenReqDTO.setGrantType(grantType);
        OAuthTokenReqMessageContext tokReqMsgCtx = new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO);
        tokReqMsgCtx.setScope(scopeArray);

        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
        );
        assertTrue(oidcScopeHandler.validateScope(tokReqMsgCtx), "Scope validation failed for grant type: "
                + grantType);
    }

    @DataProvider(name = "CanHandleData")
    public Object[][] canHandleData() {
        String[] scopeArray1 = new String[]{"scope1", "scope2", "scope3"};
        String[] scopeArray2 = new String[]{OAuthConstants.Scope.OPENID, "scope2", "scope3"};

        return new Object[][]{
                // scopes
                // expected result
                {scopeArray1, false},
                {scopeArray2, true}
        };
    }

    @Test(dataProvider = "CanHandleData")
    public void testCanHandle(String[] scopes, boolean expectedResult) throws Exception {
        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        OAuthTokenReqMessageContext tokReqMsgCtx = new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO);
        tokReqMsgCtx.setScope(scopes);

        assertEquals(oidcScopeHandler.canHandle(tokReqMsgCtx), expectedResult);
    }

    private void setFinalField(Object object, String fieldName, Object value) throws Exception {
        Field field = object.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);
        field.set(object, value);
    }

}
