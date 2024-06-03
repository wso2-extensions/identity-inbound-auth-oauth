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

import org.mockito.Mock;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.TestConstants;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

public class OAuthUserStoreConfigListenerImplTest {

    private OAuthUserStoreConfigListenerImpl oAuthUserStoreConfigListener;
    private static final String CURRENT_USER_STORE_NAME = "current";
    private static final String NEW_USER_STORE_NAME = "new";

    @Mock
    OAuthServerConfiguration oAuthServerConfiguration;

//    @BeforeMethod
//    public void setUp() throws Exception {
//        oAuthUserStoreConfigListener = spy(new OAuthUserStoreConfigListenerImpl());
//        initMocks(this);
//        oAuthServerConfiguration = mock(OAuthServerConfiguration.class);
//        mockStatic(OAuthServerConfiguration.class);
//        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
//    }
//
//    @AfterMethod
//    public void tearDown() throws Exception {
//        reset(oAuthServerConfiguration);
//    }
//
//    @Test
//    public void testOnUserStoreNamePreUpdate() throws Exception {
//
//        oAuthUserStoreConfigListener.onUserStoreNamePreUpdate(TestConstants.TENANT_ID, CURRENT_USER_STORE_NAME,
//                NEW_USER_STORE_NAME);
//        verify(oAuthUserStoreConfigListener).onUserStoreNamePreUpdate(TestConstants.TENANT_ID, CURRENT_USER_STORE_NAME,
//                NEW_USER_STORE_NAME);
//    }
//
//    @Test
//    public void testOnUserStorePreDelete() throws Exception {
//        oAuthUserStoreConfigListener.onUserStorePreDelete(TestConstants.TENANT_ID, CURRENT_USER_STORE_NAME);
//        verify(oAuthUserStoreConfigListener).onUserStorePreDelete(TestConstants.TENANT_ID, CURRENT_USER_STORE_NAME);
//    }
}
