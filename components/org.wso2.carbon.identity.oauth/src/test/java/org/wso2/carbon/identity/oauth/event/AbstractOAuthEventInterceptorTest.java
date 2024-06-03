/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.oauth.event;

import org.mockito.MockedStatic;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfigKey;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.util.Properties;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertTrue;

/**
 * Test Class for the AbstractOauthEventInterceptor.
 */
public class AbstractOAuthEventInterceptorTest {

    private AbstractOAuthEventInterceptor testclass = new AbstractOAuthEventInterceptor();

    @Test
    public void testIsEnabled() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            IdentityEventListenerConfig identityEventListenerConfig =
                    new IdentityEventListenerConfig("true", 1, new IdentityEventListenerConfigKey(), new Properties());
            identityUtil.when(() -> IdentityUtil.readEventListenerProperty(anyString(), anyString()))
                    .thenReturn(identityEventListenerConfig);
            assertTrue(testclass.isEnabled());
            identityUtil.when(() -> IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(null);
            assertFalse(testclass.isEnabled());
        }
    }
}
