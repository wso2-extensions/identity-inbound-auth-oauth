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

package org.wso2.carbon.identity.oauth2.authz.handlers;

import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.core.persistence.JDBCPersistenceManager;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.utils.CarbonUtils;

import java.nio.file.Paths;
import java.sql.Connection;

import javax.sql.DataSource;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;

/**
 * Test class covering CodeResponseTypeHandler
 */

@WithCarbonHome
@WithH2Database(files = {"dbScripts/h2.sql", "dbScripts/identity.sql"})
@WithRealmService(tenantId = TestConstants.TENANT_ID,
        tenantDomain = TestConstants.TENANT_DOMAIN,
        initUserStoreManager = true,
        injectToSingletons = {OAuthComponentServiceHolder.class})
@PrepareForTest({PrivilegedCarbonContext.class, CarbonUtils.class, IdentityTenantUtil.class,
        IdentityUtil.class, IdentityConfigParser.class, JDBCPersistenceManager.class})
public class CodeResponseTypeHandlerTest extends PowerMockTestCase {

    private static final String TEST_CONSUMER_KEY =  "testconsumenrkey";
    private static final String TEST_CALLBACK_URL = "https://localhost:8000/callback";

    OAuthAuthzReqMessageContext authAuthzReqMessageContext;
    OAuth2AuthorizeReqDTO authorizationReqDTO;

    @Mock
    IdentityConfigParser mockConfigParser;

    Connection con = null;

    @BeforeMethod
    public void setUp() throws Exception {
        authorizationReqDTO = new OAuth2AuthorizeReqDTO();
        authorizationReqDTO.setCallbackUrl(TEST_CALLBACK_URL);
        authorizationReqDTO.setConsumerKey(TEST_CONSUMER_KEY);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("testUser");
        authenticatedUser.setTenantDomain("carbon.super");
        authenticatedUser.setUserStoreDomain("PRIMARY");
        authorizationReqDTO.setUser(authenticatedUser);
        authorizationReqDTO.setResponseType(OAuthConstants.GrantTypes.TOKEN);
        authAuthzReqMessageContext
                = new OAuthAuthzReqMessageContext(authorizationReqDTO);
        authAuthzReqMessageContext
                .setApprovedScope(new String[]{"scope1", "scope2", OAuthConstants.Scope.OPENID});
    }

    @AfterMethod
    public void tearDown() throws Exception {
    }

    /**
     * This data provider is added to enable affected test cases to be tested in both
     * where the IDP_ID column is available and not available in the relevant tables.
     */
    @DataProvider(name = "IdpIDColumnAvailabilityDataProvider")
    public Object[][] idpIDColumnAvailabilityDataProvider() {
        return new Object[][]{
                {true},
                {false}
        };
    }

    @Test(dataProvider = "IdpIDColumnAvailabilityDataProvider")
    public void testIssue(boolean isIDPIdColumnEnabled) throws Exception {

        String carbonHome = Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString();
        spy(CarbonUtils.class);
        doReturn(carbonHome).when(CarbonUtils.class, "getCarbonHome");
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(MultitenantConstants.SUPER_TENANT_ID);
        when(IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

        mockStatic(IdentityConfigParser.class);
        when(IdentityConfigParser.getInstance()).thenReturn(mockConfigParser);

        OAuth2ServiceComponentHolder.setIDPIdColumnEnabled(isIDPIdColumnEnabled);
        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setGrantTypes("implicit");
        oAuthAppDO.setOauthConsumerKey(TEST_CONSUMER_KEY);
        oAuthAppDO.setState("active");
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserStoreDomain("PRIMARY");
        user.setUserName("testUser");
        user.setFederatedIdPName(TestConstants.LOCAL_IDP);

        oAuthAppDO.setUser(user);
        oAuthAppDO.setApplicationName("testApp");

        AppInfoCache appInfoCache = AppInfoCache.getInstance();
        appInfoCache.addToCache(TEST_CONSUMER_KEY, oAuthAppDO);

        mockStatic(JDBCPersistenceManager.class);
        DataSource dataSource = Mockito.mock(DataSource.class);
        JDBCPersistenceManager jdbcPersistenceManager = Mockito.mock(JDBCPersistenceManager.class);
        Mockito.when(dataSource.getConnection()).thenReturn(con);
        Mockito.when(jdbcPersistenceManager.getInstance()).thenReturn(jdbcPersistenceManager);
        Mockito.when(jdbcPersistenceManager.getDataSource()).thenReturn(dataSource);


        CodeResponseTypeHandler codeResponseTypeHandler = new CodeResponseTypeHandler();
        codeResponseTypeHandler.init();
        OAuth2AuthorizeRespDTO oAuth2AuthorizeRespDTO =
                codeResponseTypeHandler.issue(authAuthzReqMessageContext);
        Assert.assertNotNull(oAuth2AuthorizeRespDTO.getAuthorizationCode(),
                "Access token not Authorization code");
        Assert.assertEquals(oAuth2AuthorizeRespDTO.getCallbackURI()
                , TEST_CALLBACK_URL, "Callback url not set");
    }
}
