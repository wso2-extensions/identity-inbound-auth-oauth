/*
 * Copyright (c) 2024, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.rar.token;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenProvider;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.rar.exception.AuthorizationDetailsProcessingException;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth2.rar.utils.AuthorizationDetailsBaseTest;
import org.wso2.carbon.identity.oauth2.rar.validator.AuthorizationDetailsValidator;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.OAuth2TokenValidationMessageContext;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Test class for {@link IntrospectionRARDataProvider}.
 */
@WithCarbonHome
public class IntrospectionRARDataProviderTest extends AuthorizationDetailsBaseTest {

    private AuthorizationDetailsValidator validatorMock;
    private OAuth2ServiceComponentHolder componentHolderMock;

    private IntrospectionRARDataProvider uut;

    @BeforeClass
    public void setUpClass() throws IdentityOAuth2Exception, AuthorizationDetailsProcessingException {

        this.validatorMock = Mockito.mock(AuthorizationDetailsValidator.class);
        when(validatorMock.getValidatedAuthorizationDetails(any(OAuth2TokenValidationMessageContext.class)))
                .thenReturn(authorizationDetails);

        this.uut = new IntrospectionRARDataProvider(validatorMock);

        AccessTokenDO accessTokenDO = new AccessTokenDO();

        TokenProvider tokenProviderMock = Mockito.mock(TokenProvider.class);
        when(tokenProviderMock.getVerifiedAccessToken(anyString(), anyBoolean())).thenReturn(accessTokenDO);

        this.componentHolderMock = Mockito.mock(OAuth2ServiceComponentHolder.class);
        when(componentHolderMock.getTokenProvider()).thenReturn(tokenProviderMock);
    }

    @Test(priority = 1)
    public void shouldNotReturnAuthorizationDetails_ifNotRichAuthorizationRequest()
            throws IdentityOAuth2Exception, AuthorizationDetailsProcessingException {

        when(validatorMock.getValidatedAuthorizationDetails(any(OAuth2TokenValidationMessageContext.class)))
                .thenReturn(new AuthorizationDetails());

        try (MockedStatic<OAuth2Util> oAuth2UtilMock = Mockito.mockStatic(OAuth2Util.class);
             MockedStatic<OAuth2ServiceComponentHolder> componentHolderMock =
                     Mockito.mockStatic(OAuth2ServiceComponentHolder.class)) {

            oAuth2UtilMock.when(() -> OAuth2Util.buildScopeArray(any())).thenReturn(new String[0]);
            componentHolderMock.when(OAuth2ServiceComponentHolder::getInstance)
                    .thenReturn(this.componentHolderMock);

            assertAuthorizationDetailsMissing(uut.getIntrospectionData(tokenValidationRequestDTO,
                    introspectionResponseDTO));
        }
    }

    @Test
    public void shouldReturnAuthorizationDetails_ifRichAuthorizationRequestAndContextIsMissing()
            throws IdentityOAuth2Exception {

        try (MockedStatic<OAuth2Util> oAuth2UtilMock = Mockito.mockStatic(OAuth2Util.class);
             MockedStatic<OAuth2ServiceComponentHolder> componentHolderMock =
                     Mockito.mockStatic(OAuth2ServiceComponentHolder.class)) {

            oAuth2UtilMock.when(() -> OAuth2Util.buildScopeArray(any())).thenReturn(new String[0]);
            componentHolderMock.when(OAuth2ServiceComponentHolder::getInstance)
                    .thenReturn(this.componentHolderMock);

            assertAuthorizationDetailsPresent(uut.getIntrospectionData(tokenValidationRequestDTO,
                    introspectionResponseDTO));
        }
    }

    @Test
    public void shouldReturnAuthorizationDetails_ifRichAuthorizationRequestAndContextIsPresent()
            throws IdentityOAuth2Exception {

        OAuth2TokenValidationMessageContext context = new OAuth2TokenValidationMessageContext(tokenValidationRequestDTO,
                new OAuth2TokenValidationResponseDTO());

        Map<String, Object> properties = new HashMap<>();
        properties.put(OAuth2Util.OAUTH2_VALIDATION_MESSAGE_CONTEXT, context);
        this.introspectionResponseDTO.setProperties(properties);

        try (MockedStatic<OAuth2Util> oAuth2UtilMock = Mockito.mockStatic(OAuth2Util.class)) {

            oAuth2UtilMock.when(() -> OAuth2Util.buildScopeArray(any())).thenReturn(new String[0]);
            assertAuthorizationDetailsPresent(uut.getIntrospectionData(tokenValidationRequestDTO,
                    introspectionResponseDTO));
        }
    }
}
