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

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.mgt.internal.ApplicationManagementServiceComponent;
import org.wso2.carbon.identity.application.mgt.internal.ApplicationManagementServiceComponentHolder;
import org.wso2.carbon.identity.common.testng.WithAxisConfiguration;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithKeyStore;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.test.utils.CommonTestUtils;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.identity.testutil.IdentityBaseTest;
import org.wso2.carbon.identity.testutil.ReadCertStoreSampleUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.idp.mgt.internal.IdpMgtServiceComponentHolder;
import org.wso2.carbon.user.core.service.RealmService;

import java.security.Key;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.oauth2.test.utils.CommonTestUtils.setFinalStatic;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_ID;

@WithCarbonHome
@WithAxisConfiguration
@WithH2Database(jndiName = "jdbc/WSO2IdentityDB", files = { "dbScripts/identity.sql" })
@WithRealmService(tenantId = SUPER_TENANT_ID, tenantDomain = SUPER_TENANT_DOMAIN_NAME,
        injectToSingletons = {ApplicationManagementServiceComponentHolder.class})
@WithKeyStore
public class DefaultIDTokenBuilderTest extends IdentityBaseTest {

    public static final String TEST_APPLICATION_NAME = "DefaultIDTokenBuilderTest";
    private DefaultIDTokenBuilder defaultIDTokenBuilder;
    private OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
    private OAuthTokenReqMessageContext messageContext = new OAuthTokenReqMessageContext(tokenReqDTO);
    private OAuth2AccessTokenRespDTO tokenRespDTO = new OAuth2AccessTokenRespDTO();

    @BeforeClass
    public void setUp() throws Exception {
        tokenReqDTO.setTenantDomain(SUPER_TENANT_DOMAIN_NAME);
        tokenReqDTO.setClientId(TestConstants.CLIENT_ID);
        tokenReqDTO.setCallbackURI(TestConstants.CALLBACK);

        AuthenticatedUser user = new AuthenticatedUser();
        user.setAuthenticatedSubjectIdentifier(TestConstants.USER_NAME);
        user.setUserName(TestConstants.USER_NAME);
        user.setUserStoreDomain(TestConstants.USER_STORE_DOMAIN);
        user.setTenantDomain(SUPER_TENANT_DOMAIN_NAME);
        user.setFederatedUser(false);

        messageContext.setAuthorizedUser(user);

        messageContext.setScope(TestConstants.OPENID_SCOPE_STRING.split(" "));

        tokenRespDTO.setAccessToken(TestConstants.ACCESS_TOKEN);

        IdentityProvider idp = new IdentityProvider();
        idp.setIdentityProviderName("LOCAL");
        idp.setEnable(true);

        IdentityProviderManager.getInstance().addResidentIdP(idp, SUPER_TENANT_DOMAIN_NAME);
        defaultIDTokenBuilder =  new DefaultIDTokenBuilder();

        ApplicationManagementService applicationMgtService = mock(ApplicationManagementService.class);
        OAuth2ServiceComponentHolder.setApplicationMgtService(applicationMgtService);
        Map<String, ServiceProvider> fileBasedSPs = CommonTestUtils.getFileBasedSPs();
        setFinalStatic(ApplicationManagementServiceComponent.class.getDeclaredField("fileBasedSPs"),
                                       fileBasedSPs);
        when(applicationMgtService
                     .getApplicationExcludingFileBasedSPs(TEST_APPLICATION_NAME, SUPER_TENANT_DOMAIN_NAME))
                .thenReturn(fileBasedSPs.get(TEST_APPLICATION_NAME));
        when(applicationMgtService
                     .getServiceProviderNameByClientId(TestConstants.CLIENT_ID, TestConstants.APP_TYPE,
                                                       SUPER_TENANT_DOMAIN_NAME))
                .thenReturn(TEST_APPLICATION_NAME);
        RealmService realmService = IdentityTenantUtil.getRealmService();
        HashMap<String, String> claims = new HashMap<>();
        claims.put("http://wso2.org/claims/username", TestConstants.USER_NAME);
        realmService.getTenantUserRealm(SUPER_TENANT_ID).getUserStoreManager()
                    .addUser(TestConstants.USER_NAME, TestConstants.PASSWORD, new String[0], claims,
                             TestConstants.DEFAULT_PROFILE);

        Map<Integer, Certificate> publicCerts = new ConcurrentHashMap<>();
        publicCerts.put(SUPER_TENANT_ID, ReadCertStoreSampleUtil.createKeyStore(getClass())
                                                                .getCertificate("wso2carbon"));
        setFinalStatic(OAuth2Util.class.getDeclaredField("publicCerts"), publicCerts);
        Map<Integer, Key> privateKeys = new ConcurrentHashMap<>();
        privateKeys.put(SUPER_TENANT_ID, ReadCertStoreSampleUtil.createKeyStore(getClass())
                                                                .getKey("wso2carbon", "wso2carbon".toCharArray()));
        setFinalStatic(OAuth2Util.class.getDeclaredField("privateKeys"), privateKeys);

        OpenIDConnectServiceComponentHolder.getInstance()
                .getOpenIDConnectClaimFilters().add(new OpenIDConnectClaimFilterImpl());
    }


    @Test
    public void testBuildIDToken() throws Exception {
        RealmService realmService = IdentityTenantUtil.getRealmService();
        PrivilegedCarbonContext.getThreadLocalCarbonContext()
                               .setUserRealm(realmService.getTenantUserRealm(SUPER_TENANT_ID));
        IdpMgtServiceComponentHolder.getInstance().setRealmService(IdentityTenantUtil.getRealmService());
        defaultIDTokenBuilder.buildIDToken(messageContext, tokenRespDTO);
    }

}
