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

import org.apache.commons.dbcp.BasicDataSource;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuer;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithAxisConfiguration;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.persistence.JDBCPersistenceManager;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientApplicationDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuerImpl;
import org.wso2.carbon.identity.openidconnect.util.TestUtils;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.sql.Connection;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;

import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertNotNull;

@WithCarbonHome
@WithAxisConfiguration
@PowerMockIgnore({"javax.xml.*", "org.xml.sax.*", "org.w3c.dom.*"})
@PrepareForTest({OAuthServerConfiguration.class, JDBCPersistenceManager.class, IdentityDatabaseUtil.class,
        RealmService.class})
public class TokenValidationHandlerTest extends PowerMockTestCase {

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
    private static final String DEFAULT_TOKEN_TYPE = "Default";
    private static final String JWT_TOKEN_TYPE = "JWT";
    private static final String DB_NAME = "jdbc/WSO2IdentityDB";
    private static final String H2_SCRIPT_NAME = "token.sql";
    private Connection conn = null;

    @Mock
    private OAuth2TokenValidator tokenValidator;
    @Mock
    private OAuthIssuer oAuthIssuer;
    @Mock
    protected OAuthServerConfiguration oAuthServerConfiguration;
    @Mock
    private RealmService realmService;
    @Mock
    private TenantManager tenantManager;
    @Mock
    private RealmConfiguration realmConfiguration;

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

        mockRequiredObjects();
        OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO = new OAuth2TokenValidationRequestDTO();
        OAuth2TokenValidationRequestDTO.OAuth2AccessToken oAuth2AccessToken =
                oAuth2TokenValidationRequestDTO.new OAuth2AccessToken();
        oAuth2AccessToken.setIdentifier("testIdentifier");
        oAuth2AccessToken.setTokenType("bearer");
        oAuth2TokenValidationRequestDTO.setAccessToken(oAuth2AccessToken);

        OAuth2ClientApplicationDTO response = tokenValidationHandler
                .findOAuthConsumerIfTokenIsValid(oAuth2TokenValidationRequestDTO);
        assertNotNull(response);
    }

    @Test
    public void testBuildIntrospectionResponse() throws Exception {

        mockRequiredObjects();
        when(realmService.getTenantManager()).thenReturn(tenantManager);
        doReturn(MultitenantConstants.SUPER_TENANT_ID).when(tenantManager).getTenantId(Mockito.anyString());
        OAuthComponentServiceHolder.getInstance().setRealmService(realmService);
        IdentityTenantUtil.setRealmService(realmService);
        when(realmService.getBootstrapRealmConfiguration()).thenReturn(realmConfiguration);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn("PRIMARY");

        OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO = new OAuth2TokenValidationRequestDTO();
        OAuth2TokenValidationRequestDTO.OAuth2AccessToken accessToken = oAuth2TokenValidationRequestDTO.new
                OAuth2AccessToken();
        String ACCESS_TOKEN = "testAccessToken";
        accessToken.setIdentifier(ACCESS_TOKEN);
        accessToken.setTokenType("bearer");

        AccessTokenDO accessTokenDO = new AccessTokenDO(clientId, authzUser, scopeArraySorted, issuedTime,
                refreshTokenIssuedTime, validityPeriodInMillis, refreshTokenValidityPeriodInMillis, tokenType,
                authorizationCode);
        accessTokenDO.setTokenId("1234");

        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setTokenType("Default");
        oAuthAppDO.setApplicationName("testApp");
        AppInfoCache appInfoCache = AppInfoCache.getInstance();
        appInfoCache.addToCache("testConsumerKey", oAuthAppDO);
        tokenMgtDAO.persistAccessToken(ACCESS_TOKEN, "testConsumerKey", accessTokenDO, accessTokenDO,
                "TESTDOMAIN");
        oAuth2TokenValidationRequestDTO.setAccessToken(accessToken);

        assertNotNull(tokenValidationHandler.buildIntrospectionResponse(oAuth2TokenValidationRequestDTO));
    }

    protected void mockRequiredObjects() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(OAuthServerConfiguration.getInstance().getOAuthTokenGenerator()).thenReturn(oAuthIssuer);
        when(OAuthServerConfiguration.getInstance().getSignatureAlgorithm()).thenReturn("SHA256withRSA");
        when(OAuthServerConfiguration.getInstance().getHashAlgorithm()).thenReturn("SHA-256");

        Map<String, OauthTokenIssuer> oauthTokenIssuerMap = new HashMap<>();
        oauthTokenIssuerMap.put(DEFAULT_TOKEN_TYPE, new OauthTokenIssuerImpl());
        oauthTokenIssuerMap.put(JWT_TOKEN_TYPE, new JWTTokenIssuer());
        when(OAuthServerConfiguration.getInstance().getOauthTokenIssuerMap()).thenReturn(oauthTokenIssuerMap);

        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(getDBConnection());
    }

    private Connection getDBConnection() throws Exception {

        if (conn == null) {
            BasicDataSource dataSource = new BasicDataSource();
            dataSource.setDriverClassName("org.h2.Driver");
            dataSource.setUsername("username");
            dataSource.setPassword("password");
            dataSource.setUrl("jdbc:h2:mem:test" + DB_NAME);
            try (Connection connection = dataSource.getConnection()) {
                connection.createStatement().executeUpdate("RUNSCRIPT FROM '" + TestUtils.getFilePath(H2_SCRIPT_NAME) + "'");
            }
            conn = dataSource.getConnection();
        }
        return conn;
    }
}
