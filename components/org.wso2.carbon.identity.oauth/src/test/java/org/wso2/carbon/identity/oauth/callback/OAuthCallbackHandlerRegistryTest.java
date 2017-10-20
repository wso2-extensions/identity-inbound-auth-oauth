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

package org.wso2.carbon.identity.oauth.callback;

import org.apache.commons.lang.StringUtils;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.config.OAuthCallbackHandlerMetaData;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.lang.reflect.Field;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

/**
 * Unit tests for OAuthCallbackHandlerRegistryTest.
 */
@PrepareForTest({OAuthServerConfiguration.class})
public class OAuthCallbackHandlerRegistryTest extends PowerMockIdentityBaseTest {

    private static final int ZERO = 0;
    private static final int TWO = 2;

    @Mock
    private OAuthServerConfiguration oAuthServerConfiguration;

    @DataProvider(name = "testGetOAuthAuthzHandler")
    public Object[][] oAuthHandlerClassName() {
        return new Object[][] {
                {"org.wso2.carbon.identity.oauth.callback.DefaultCallbackHandler"},
                {null}
        };
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testGetInstance() throws Exception {
        String className = "org.wso2.carbon.identity.oauth.callback.NonExistingCallbackHandler";
        getOAuthCallbackHandlerRegistry(className, TWO);
    }

    @Test(dataProvider = "testGetOAuthAuthzHandler")
    public void testGetOAuthAuthzHandler(String className) throws Exception {

        // Create OAuthCallbackHandlerRegistry.
        OAuthCallbackHandlerRegistry oAuthCallbackHandlerRegistry = getOAuthCallbackHandlerRegistry(className, TWO);
        // Create OAuthCallback to be handled.
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        OAuthCallback oAuthCallback = new OAuthCallback(authenticatedUser, "client", OAuthCallback.OAuthCallbackType
                .ACCESS_DELEGATION_AUTHZ);
        oAuthCallback.setAuthorized(false);
        oAuthCallback.setValidScope(false);
        // Get the OAuthCallBackHandler that can handle the above OAuthCallback.
        OAuthCallbackHandler oAuthCallbackHandler = oAuthCallbackHandlerRegistry.getOAuthAuthzHandler(oAuthCallback);

        if (StringUtils.isNotEmpty(className)) {
            assertEquals(oAuthCallbackHandler.getPriority(), ZERO, "OAuthHandlers priority should be equal to" +
                    " the given priority in the OAuthCallBackHandlerMetaData.");
        } else {
            assertNull(oAuthCallbackHandler, "Should return null when there is no OAuthCallbackHandler can handle the" +
                    " given OAuthCallback.");
        }
    }

    private OAuthCallbackHandlerRegistry getOAuthCallbackHandlerRegistry(String className, int metaDataSetSize)
            throws IdentityOAuth2Exception, NoSuchFieldException, IllegalAccessException {

        // Clear the OAuthCallbackHandlerRegistry.
        Field instance = OAuthCallbackHandlerRegistry.class.getDeclaredField("instance");
        instance.setAccessible(true);
        instance.set(null, null);

        // Mock oAuthServerConfiguration to have the MetaData of the given OAuthCallbackHandler.
        Set<OAuthCallbackHandlerMetaData> oAuthCallbackHandlerMetaDataSet = new HashSet<>();
        for (int i = ZERO; i < metaDataSetSize; i++){
            if (StringUtils.isNotEmpty(className)) {
                OAuthCallbackHandlerMetaData oAuthCallbackHandlerMetaData = new OAuthCallbackHandlerMetaData(className,
                        new Properties(), i);
                oAuthCallbackHandlerMetaDataSet.add(oAuthCallbackHandlerMetaData);
            }
        }
        when(oAuthServerConfiguration.getCallbackHandlerMetaData()).thenReturn(oAuthCallbackHandlerMetaDataSet);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);

        return OAuthCallbackHandlerRegistry.getInstance();
    }
}
