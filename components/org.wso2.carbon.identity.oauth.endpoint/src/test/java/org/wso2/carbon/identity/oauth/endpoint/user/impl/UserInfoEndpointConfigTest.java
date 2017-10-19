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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.user.impl;

import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.IObjectFactory;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth.user.UserInfoAccessTokenValidator;
import org.wso2.carbon.identity.oauth.user.UserInfoClaimRetriever;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth.user.UserInfoRequestValidator;
import org.wso2.carbon.identity.oauth.user.UserInfoResponseBuilder;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;

import java.util.Map;
import javax.servlet.http.HttpServletRequest;

import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

@PrepareForTest({EndpointUtil.class})
public class UserInfoEndpointConfigTest extends PowerMockTestCase {

    @Mock
    private EndpointUtil endpointUtil;
    @Mock
    private OAuthServerConfiguration oAuthServerConfiguration;
    private final String NON_EXISTING_CLASS = "org.wso2.carbon.identity.NonExistingClass";

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }

    @Test
    public void testGetInstance() throws Exception {
        assertNotNull(UserInfoEndpointConfig.getInstance(), "UserInfoEndpoint config is expected not to be null");
    }

    @DataProvider
    public Object[][] getUserInfoRequestValidator() {
        return new Object[][]{
                {NON_EXISTING_CLASS, null, false},
                {TestUserInfoRequestValidator.class.getName(), null, false},
                {org.wso2.carbon.identity.oauth.endpoint.user.impl.extension.TestUserInfoRequestValidator.class.getName(),
                        null, false},
                {UserInforRequestDefaultValidator.class.getName(), UserInforRequestDefaultValidator.class, true},
                {NON_EXISTING_CLASS, UserInforRequestDefaultValidator.class, true},
        };
    }

    @Test(dataProvider = "getUserInfoRequestValidator")
    public void testGetUserInfoRequestValidator(String validatorClass, Class validatorClassType, boolean
            isClassExisting) throws Exception {
        mockStatic(EndpointUtil.class);
        when(EndpointUtil.getUserInfoRequestValidator()).thenReturn(validatorClass);
        UserInfoRequestValidator userInfoRequestValidator = UserInfoEndpointConfig.getInstance()
                .getUserInfoRequestValidator();

        if (isClassExisting) {
            assertNotNull(userInfoRequestValidator, "UserInfoRequest builder should not be null for class " +
                    validatorClass);
            assertEquals(validatorClassType, userInfoRequestValidator.getClass(), "Expected type of UserInfoValidator" +
                    " was not found");
        } else {
            assertNull(userInfoRequestValidator, "Non-existing or invalid class passed. Hence validator should be " +
                    "null");
        }
    }

    @DataProvider
    public Object[][] getAccessTokenValidators() {
        return new Object[][]{
                {NON_EXISTING_CLASS, null, false},
                {TestUserInfoValidator.class.getName(), null, false},
                {org.wso2.carbon.identity.oauth.endpoint.user.impl.extension.TestUserInfoValidator.class.getName(),
                        null, false},
                {UserInfoISAccessTokenValidator.class.getName(), UserInfoISAccessTokenValidator.class, true},
                {NON_EXISTING_CLASS, UserInfoISAccessTokenValidator.class, true},
        };
    }

    @Test(dataProvider = "getAccessTokenValidators")
    public void testGetUserUserInfoAccessTokenValidator(String validatorClass, Class validatorClassType, boolean
            isClassExisting) throws Exception {
        mockStatic(EndpointUtil.class);
        when(EndpointUtil.getAccessTokenValidator()).thenReturn(validatorClass);
        UserInfoAccessTokenValidator userInfoAccessTokenValidator = UserInfoEndpointConfig.getInstance()
                .getUserInfoAccessTokenValidator();

        if (isClassExisting) {
            assertNotNull(userInfoAccessTokenValidator, "AccessTokenValidator should not be null for class " +
                    validatorClass);
            assertEquals(validatorClassType, userInfoAccessTokenValidator.getClass(), "Expected type of " +
                    "AccessTokenValidator was not found");
        } else {
            assertNull(userInfoAccessTokenValidator, "Non-existing or invalid class passed. Hence validator should be " +
                    "null");
        }
    }

    @DataProvider
    public Object[][] getUserInfoResponseBuilder() {
        return new Object[][]{
                {NON_EXISTING_CLASS, null, false},
                {TesUserInfoResponseBuilder.class.getName(), null, false},
                {org.wso2.carbon.identity.oauth.endpoint.user.impl.extension.TesUserInfoResponseBuilder.class.getName
                        (), null, false},
                {UserInfoJSONResponseBuilder.class.getName(), UserInfoJSONResponseBuilder.class, true},
                {NON_EXISTING_CLASS, UserInfoJSONResponseBuilder.class, true},
        };
    }

    @Test(dataProvider = "getUserInfoResponseBuilder")
    public void testGetUserInfoResponseBuilder(String validatorClass, Class validatorClassType, boolean
            isClassExisting) throws Exception {
        mockStatic(EndpointUtil.class);
        when(EndpointUtil.getUserInfoResponseBuilder()).thenReturn(validatorClass);
        UserInfoResponseBuilder userInfoResponseBuilder = UserInfoEndpointConfig.getInstance()
                .getUserInfoResponseBuilder();

        if (isClassExisting) {
            assertNotNull(userInfoResponseBuilder, "UserInfoResponseBuilder should not be null for class " +
                    validatorClass);
            assertEquals(validatorClassType, userInfoResponseBuilder.getClass(), "Expected type of " +
                    "UserInfoResponseBuilder was not found");
        } else {
            assertNull(userInfoResponseBuilder, "Non-existing or invalid class passed. Hence validator should be " +
                    "null");
        }
    }

    @DataProvider
    public Object[][] getUserUserInfoClaimRetriever() {
        return new Object[][]{
                {NON_EXISTING_CLASS, null, false},
                {TestUserInfoClaimRetriever.class.getName(), null, false},
                {org.wso2.carbon.identity.oauth.endpoint.user.impl.extension.TestUserInfoClaimRetriever.class.getName
                        (), null, false},
                {UserInfoUserStoreClaimRetriever.class.getName(), UserInfoUserStoreClaimRetriever.class, true},
                {NON_EXISTING_CLASS, UserInfoUserStoreClaimRetriever.class, true},
        };
    }

    @Test(dataProvider = "getUserUserInfoClaimRetriever")
    public void testGetUserInfoClaimRetriever(String validatorClass, Class validatorClassType, boolean
            isClassExisting) throws Exception {
        mockStatic(EndpointUtil.class);
        when(EndpointUtil.getUserInfoClaimRetriever()).thenReturn(validatorClass);
        UserInfoClaimRetriever userInfoClaimRetriever = UserInfoEndpointConfig.getInstance()
                .getUserInfoClaimRetriever();

        if (isClassExisting) {
            assertNotNull(userInfoClaimRetriever, "UserInfoResponseBuilder should not be null for class " +
                    validatorClass);
            assertEquals(validatorClassType, userInfoClaimRetriever.getClass(), "Expected type of " +
                    "UserInfoClaimRetriever was not found");
        } else {
            assertNull(userInfoClaimRetriever, "Non-existing or invalid class passed. Hence validator should be " +
                    "null");
        }
    }

    /**
     * This is just a sample extension class which will cause InstantiationException while instantiating
     */
    public class TestUserInfoValidator implements UserInfoAccessTokenValidator {
        @Override
        public OAuth2TokenValidationResponseDTO validateToken(String accessToken) throws UserInfoEndpointException {
            // Do Nothing
            return null;
        }
    }

    /**
     * This is just a sample extension class which will cause InstantiationException while instantiating
     */
    public class TesUserInfoResponseBuilder implements UserInfoResponseBuilder {
        @Override
        public String getResponseString(OAuth2TokenValidationResponseDTO tokenResponse) throws
                UserInfoEndpointException, OAuthSystemException {
            // Do nothing.
            return null;
        }
    }

    /**
     * This is just a sample extension class which will cause InstantiationException while instantiating
     */
    public class TestUserInfoClaimRetriever implements UserInfoClaimRetriever {
        @Override
        public Map<String, Object> getClaimsMap(Map<ClaimMapping, String> userAttributes) {
            // Do Nothing.
            return null;
        }
    }

    /**
     * This is just a sample extension class which will cause InstantiationException while instantiating
     */
    public class TestUserInfoRequestValidator implements UserInfoRequestValidator {
        @Override
        public String validateRequest(HttpServletRequest request) throws UserInfoEndpointException {
            // Do Nothing
            return null;
        }
    }
}