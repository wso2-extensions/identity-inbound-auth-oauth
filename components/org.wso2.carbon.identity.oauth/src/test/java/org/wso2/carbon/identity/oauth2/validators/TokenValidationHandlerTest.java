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

import org.mockito.Mock;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithAxisConfiguration;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientApplicationDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.user.core.service.RealmService;

import java.sql.Timestamp;

import static org.testng.Assert.assertNotNull;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_ID;

@WithCarbonHome
@WithAxisConfiguration
@WithH2Database(jndiName = "jdbc/WSO2IdentityDB", files = {"dbScripts/token.sql"})
@WithRealmService(tenantId = MultitenantConstants.SUPER_TENANT_ID)
public class TokenValidationHandlerTest {

    private String scopeArraySorted[] = new String[]{"scope1", "scope2", "scope3"};
    private String clientId = "dummyClientId";
    private String authorizationCode = "testAuthorizationCode";
    private String tokenType = "testTokenType";
    private AuthenticatedUser authzUser;
    private Timestamp issuedTime;
    private Timestamp refreshTokenIssuedTime;
    private long validityPeriodInMillis;
    private long refreshTokenValidityPeriodInMillis;
    private TokenMgtDAO tokenMgtDAO;

    @Mock
    private OAuth2TokenValidator tokenValidator;

    private TokenValidationHandler tokenValidationHandler;

    @BeforeMethod
    public void setUp() {
        authzUser = new AuthenticatedUser();
        tokenMgtDAO = new TokenMgtDAO();
        issuedTime = new Timestamp(System.currentTimeMillis());
        refreshTokenIssuedTime = new Timestamp(System.currentTimeMillis());
        validityPeriodInMillis = 3600000L;
        refreshTokenValidityPeriodInMillis = 3600000L;
        tokenValidationHandler = TokenValidationHandler.getInstance();
        tokenValidationHandler.addTokenValidator("test", tokenValidator);
    }

    @Test
    public void testGetInstance() throws Exception {
        assertNotNull(tokenValidationHandler);
    }

    @Test
    public void testValidate() throws Exception {
        OAuth2TokenValidationResponseDTO responseDTO = tokenValidationHandler
                .validate(new OAuth2TokenValidationRequestDTO());
        assertNotNull(responseDTO);
    }

    @Test
    public void testFindOAuthConsumerIfTokenIsValid() throws Exception {
        OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO = new OAuth2TokenValidationRequestDTO();
        OAuth2TokenValidationRequestDTO.OAuth2AccessToken oAuth2AccessToken = oAuth2TokenValidationRequestDTO.new OAuth2AccessToken();
        oAuth2AccessToken.setIdentifier("testIdentifier");
        oAuth2AccessToken.setTokenType("bearer");
        oAuth2TokenValidationRequestDTO.setAccessToken(oAuth2AccessToken);

        OAuth2ClientApplicationDTO response = tokenValidationHandler
                .findOAuthConsumerIfTokenIsValid(oAuth2TokenValidationRequestDTO);
        assertNotNull(response);
    }

    @Test
    public void testBuildIntrospectionResponse() throws Exception {
        RealmService realmService = IdentityTenantUtil.getRealmService();
        PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .setUserRealm(realmService.getTenantUserRealm(SUPER_TENANT_ID));
        OAuthComponentServiceHolder.getInstance().setRealmService(IdentityTenantUtil.getRealmService());

        OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO = new OAuth2TokenValidationRequestDTO();
        OAuth2TokenValidationRequestDTO.OAuth2AccessToken accessToken = oAuth2TokenValidationRequestDTO.new
                OAuth2AccessToken();
        accessToken.setIdentifier("testAccessToken");
        accessToken.setTokenType("bearer");

        AccessTokenDO accessTokenDO = new AccessTokenDO(clientId, authzUser, scopeArraySorted, issuedTime,
                refreshTokenIssuedTime, validityPeriodInMillis, refreshTokenValidityPeriodInMillis, tokenType,
                authorizationCode);
        accessTokenDO.setTokenId("1234");
        tokenMgtDAO.persistAccessToken("testAccessToken", "testConsumerKey", accessTokenDO, accessTokenDO,
                "TESTDOMAIN");
        oAuth2TokenValidationRequestDTO.setAccessToken(accessToken);

        assertNotNull(tokenValidationHandler.buildIntrospectionResponse(oAuth2TokenValidationRequestDTO));
    }

}
