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

import org.apache.commons.lang.StringUtils;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.ResourceScopeCacheEntry;
import org.wso2.carbon.identity.testutil.IdentityBaseTest;

import static org.testng.Assert.assertEquals;

/**
 * Tests JDBCScopeValidator.
 */
@WithCarbonHome
@WithH2Database(files = {"dbScripts/scope.sql"})
@WithRealmService(tenantId = MultitenantConstants.SUPER_TENANT_ID)
public class JDBCScopeValidatorTest extends IdentityBaseTest {

    private JDBCScopeValidator validator;

    @BeforeMethod
    public void setUp()
    {
        validator = new JDBCScopeValidator();
    }

    @DataProvider(name = "ValidateScopeData")
    public Object[][] validateScopeData() {
        String[] scopeArray1 = new String[]{"scope1", "scope2", "scope3"};

        return new Object[][]{
                // scopes
                // scope
                // resource
                // expectedResult
                {scopeArray1, "scope1", null, true},
                {null, "scope2", "testResource", true},
                {new String[0], "scope3", "testResource", true},
                {scopeArray1, null, "testResource", true},
                {scopeArray1, "scope4", "testResource", false},
                {scopeArray1, "scope1", "testResource", false}
        };
    }

    @Test(dataProvider = "ValidateScopeData")
    public void testValidateScope(String[] scopes, String scope, String resource, boolean expectedResult) throws
            Exception {
        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setScope(scopes);
        AuthenticatedUser user1 = new AuthenticatedUser();
        OAuthComponentServiceHolder.getInstance().setRealmService(IdentityTenantUtil.getRealmService());
        user1.setUserName("user1@carbon.super");
        accessTokenDO.setAuthzUser(user1);
        ResourceScopeCacheEntry result = new ResourceScopeCacheEntry(scope);
        result.setTenantId(-1234);
        OAuthCache oAuthCache = OAuthCache.getInstance();
        OAuthCacheKey oAuthCacheKey;
        if (StringUtils.isNotEmpty(resource)) {
            oAuthCacheKey = new OAuthCacheKey(resource);
        } else {
            oAuthCacheKey = new OAuthCacheKey("testResource");
        }
        oAuthCache.addToCache(oAuthCacheKey, result);

        assertEquals(validator.validateScope(accessTokenDO, resource), expectedResult);
        oAuthCache.clearCacheEntry(oAuthCacheKey);
    }

}
