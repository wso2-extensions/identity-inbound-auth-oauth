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

package org.wso2.carbon.identity.oauth2.internal;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

@WithCarbonHome
@WithH2Database(files = "dbScripts/identity.sql")
@WithRealmService(injectToSingletons = IdentityTenantUtil.class)
public class OAuthUserStoreConfigListenerImplTest {

    private OAuthUserStoreConfigListenerImpl oAuthUserStoreConfigListener;
    private static final String CURRENT_USER_STORE_NAME = "current";
    private static final String NEW_USER_STORE_NAME = "new";


    @BeforeMethod
    public void setUp() throws Exception {
        oAuthUserStoreConfigListener = spy(new OAuthUserStoreConfigListenerImpl());
    }


    @DataProvider(name = "BuildAccessTokens")
    public Object[][] buildAccessTokens() {
        Set<AccessTokenDO> accessTokenDOSet = new HashSet<>();
        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setAuthzUser(new AuthenticatedUser());
        accessTokenDOSet.add(accessTokenDO);
        return new Object[][]{
                {Collections.EMPTY_SET},
                {accessTokenDOSet}
        };
    }

    @Test(dataProvider = "BuildAccessTokens")
    public void testOnUserStoreNamePreUpdate(Object tokensSet) throws Exception {
        Set<AccessTokenDO> accessTokens = (Set<AccessTokenDO>) tokensSet;
        oAuthUserStoreConfigListener.onUserStoreNamePreUpdate(TestConstants.TENANT_ID, CURRENT_USER_STORE_NAME,
                NEW_USER_STORE_NAME);
        verify(oAuthUserStoreConfigListener).onUserStoreNamePreUpdate(TestConstants.TENANT_ID, CURRENT_USER_STORE_NAME,
                NEW_USER_STORE_NAME);
    }

    @Test(dataProvider = "BuildAccessTokens")
    public void testOnUserStorePreDelete(Object tokensSet) throws Exception {
        Set<AccessTokenDO> accessTokens = (Set<AccessTokenDO>) tokensSet;
        List<AuthzCodeDO> authzCodeDOList = new ArrayList<>();
        authzCodeDOList.add(new AuthzCodeDO());
        oAuthUserStoreConfigListener.onUserStorePreDelete(TestConstants.TENANT_ID, CURRENT_USER_STORE_NAME);
        verify(oAuthUserStoreConfigListener).onUserStorePreDelete(TestConstants.TENANT_ID, CURRENT_USER_STORE_NAME);
    }
}
