/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.endpoint.user.impl;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.testng.IObjectFactory;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;

import java.util.HashMap;
import java.util.Map;

import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertNotNull;
import static org.wso2.carbon.identity.core.util.IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;

@PrepareForTest({OAuthServerConfiguration.class, FrameworkUtils.class})
public class UserInfoUserStoreClaimRetrieverTest {

    @Mock
    OAuthServerConfiguration oAuthServerConfiguration;

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new PowerMockObjectFactory();
    }

    @DataProvider
    public Object[][] getUserAttributes() {

        ClaimMapping map1 = ClaimMapping.build("localClaimUri1", "remoteClaimUri1", "defaultValue1", true);
        ClaimMapping map2 = ClaimMapping.build("localClaimUri2", "remoteClaimUri2", "defaultValue1", true);
        Map<ClaimMapping, Object> claims1 = new HashMap<>();
        Map<ClaimMapping, Object> claims2 = new HashMap<>();
        claims1.put(map1, "User1");
        claims2.put(map2, "User1, User2");
        return new Object[][] {
                {claims1},
                {claims2}
        };
    }

    @Test(dataProvider = "getUserAttributes")
    public void testUserInfoUserStoreClaimRetriever(HashMap<ClaimMapping, String> claims) {

        mockStatic(FrameworkUtils.class);
        when(FrameworkUtils.getMultiAttributeSeparator()).thenReturn(MULTI_ATTRIBUTE_SEPARATOR_DEFAULT);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.isEnableMultiValueSupport()).thenReturn(true);
        UserInfoUserStoreClaimRetriever claimsRetriever = new UserInfoUserStoreClaimRetriever();
        assertNotNull(claimsRetriever.getClaimsMap(claims));
    }
}
