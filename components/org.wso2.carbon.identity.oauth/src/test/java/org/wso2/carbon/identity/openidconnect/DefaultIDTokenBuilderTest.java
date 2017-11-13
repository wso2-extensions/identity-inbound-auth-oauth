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
import org.wso2.carbon.identity.application.mgt.internal.ApplicationManagementServiceComponentHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.test.utils.CommonTestUtils;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithKeyStore;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.common.testng.WithAxisConfiguration;
import org.wso2.carbon.identity.testutil.IdentityBaseTest;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.idp.mgt.internal.IdpMgtServiceComponentHolder;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Map;

import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_ID;

@WithCarbonHome
@WithAxisConfiguration
@WithH2Database(jndiName = "jdbc/WSO2IdentityDB", files = { "dbScripts/identity.sql" })
@WithRealmService(tenantId = SUPER_TENANT_ID, tenantDomain = SUPER_TENANT_DOMAIN_NAME, initUserStoreManager = true)
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
        user.setTenantDomain(SUPER_TENANT_DOMAIN_NAME);
        user.setFederatedUser(false);

        messageContext.setAuthorizedUser(user);

        messageContext.setScope(TestConstants.OPENID_SCOPE_STRING.split(" "));

        IdentityProvider idp = new IdentityProvider();
        idp.setIdentityProviderName("LOCAL");
        idp.setEnable(true);

        IdentityProviderManager.getInstance().addResidentIdP(idp, SUPER_TENANT_DOMAIN_NAME);
        defaultIDTokenBuilder =  new DefaultIDTokenBuilder();

        OAuth2ServiceComponentHolder.setApplicationMgtService(ApplicationManagementService.getInstance());
        RealmService realmService = IdentityTenantUtil.getRealmService();
        ApplicationManagementServiceComponentHolder.getInstance().setRealmService(realmService);
        PrivilegedCarbonContext.getThreadLocalCarbonContext()
                               .setUserRealm(realmService.getTenantUserRealm(SUPER_TENANT_ID));
        Map<String, ServiceProvider> fileBasedSPs = CommonTestUtils.getFileBasedSPs();
//        for (Map.Entry<String, ServiceProvider> serviceProviderEntry : fileBasedSPs.entrySet()) {
//            ApplicationManagementService.getInstance().createApplication(serviceProviderEntry.getValue(),
//                                                                         SUPER_TENANT_DOMAIN_NAME,
//                                                                         TestConstants.USER_NAME);
//        }
    }


    @Test
    public void testBuildIDToken() throws Exception {
//        RealmService realmService = IdentityTenantUtil.getRealmService();
//        PrivilegedCarbonContext.getThreadLocalCarbonContext()
//                               .setUserRealm(realmService.getTenantUserRealm(SUPER_TENANT_ID));
//        IdpMgtServiceComponentHolder.getInstance().setRealmService(IdentityTenantUtil.getRealmService());
//        defaultIDTokenBuilder.buildIDToken(messageContext, tokenRespDTO);
    }

}
