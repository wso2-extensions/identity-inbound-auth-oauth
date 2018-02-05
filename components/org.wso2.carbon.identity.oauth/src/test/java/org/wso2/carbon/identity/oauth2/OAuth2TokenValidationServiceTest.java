/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.oauth2;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientApplicationDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.validators.TokenValidationHandler;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyMap;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

@PrepareForTest({TokenValidationHandler.class, OAuthComponentServiceHolder.class})
public class OAuth2TokenValidationServiceTest extends PowerMockTestCase {
    private OAuth2TokenValidationService tokenValidationService;

    @Mock
    private OAuth2TokenValidationRequestDTO mockedTokenValidationRequestDTO;

    @Mock
    private TokenValidationHandler mockedValidationHandler;

    @Mock
    private OAuthComponentServiceHolder mockedOAuthComponentServiceHolder;

    @Mock
    private OAuthEventInterceptor mockedOAuthEventInterceptor;

    @Mock
    private OAuth2TokenValidationResponseDTO mockedOAuth2TokenValidationResponseDTO;

    @Mock
    private OAuth2IntrospectionResponseDTO mockedIntrospectionResponseDTO;

    @Mock
    private OAuth2TokenValidationRequestDTO mockedOAuth2TokenValidationRequestDTO;

    @Mock
    private OAuth2ClientApplicationDTO mockedClientApplicationDTO;

    @BeforeMethod
    public void setUp() throws Exception {
        tokenValidationService = new OAuth2TokenValidationService();

        mockStatic(TokenValidationHandler.class);
        when(TokenValidationHandler.getInstance()).thenReturn(mockedValidationHandler);

        mockStatic(OAuthComponentServiceHolder.class);
        when(OAuthComponentServiceHolder.getInstance()).thenReturn(mockedOAuthComponentServiceHolder);
        when(mockedOAuthComponentServiceHolder.getOAuthEventInterceptorProxy()).thenReturn(mockedOAuthEventInterceptor);
    }

    @Test
    public void testValidate() throws Exception {
        when(mockedOAuthEventInterceptor.isEnabled()).thenReturn(true, false);
        when(mockedValidationHandler.validate(any(OAuth2TokenValidationRequestDTO.class))).thenReturn
                (mockedOAuth2TokenValidationResponseDTO);

        assertNotNull(tokenValidationService.validate(mockedTokenValidationRequestDTO), "Expected a not null object.");
    }

    @Test
    public void testValidateWithErrorResponse() throws Exception {
        when(mockedOAuthEventInterceptor.isEnabled()).thenReturn(true);
        doThrow(new IdentityOAuth2Exception("dummyException")).when(mockedOAuthEventInterceptor).onPreTokenValidation
                (any(OAuth2TokenValidationRequestDTO.class), anyMap());

        OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO = tokenValidationService.validate(mockedTokenValidationRequestDTO);
        assertNotNull(oAuth2TokenValidationResponseDTO, "Expected a not null object");
        assertEquals(oAuth2TokenValidationResponseDTO.getErrorMsg(), "dummyException", "Expected error message did not received");
    }

    @Test
    public void testValidateWithErrorResponse2() throws Exception {
        String errorMsg = "Server error occurred while validating the OAuth2 access token";
        when(mockedOAuthEventInterceptor.isEnabled()).thenReturn(true);

        doThrow(new IdentityOAuth2Exception("dummyException")).when(mockedValidationHandler).validate(any
                (OAuth2TokenValidationRequestDTO.class));

        OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO = tokenValidationService.validate
                (mockedTokenValidationRequestDTO);
        assertNotNull(oAuth2TokenValidationResponseDTO, "Expected a not null object");
        assertEquals(oAuth2TokenValidationResponseDTO.getErrorMsg(), errorMsg, "Expected error message did not received");
    }

    @Test
    public void testValidateWithPrePostValidation() throws Exception {
        when(mockedOAuthComponentServiceHolder.getOAuthEventInterceptorProxy()).thenReturn(null);

        when(mockedValidationHandler.validate(any(OAuth2TokenValidationRequestDTO.class))).thenReturn
                (mockedOAuth2TokenValidationResponseDTO);

        assertNotNull(tokenValidationService.validate(mockedTokenValidationRequestDTO), "Expected to be not null");
    }

    @Test
    public void testFindOAuthConsumerIfTokenIsValid() throws Exception {
        when(mockedValidationHandler.findOAuthConsumerIfTokenIsValid(any(OAuth2TokenValidationRequestDTO.class)))
                .thenReturn(mockedClientApplicationDTO);

        OAuth2ClientApplicationDTO oAuth2ClientApplicationDTO = tokenValidationService.findOAuthConsumerIfTokenIsValid
                (mockedTokenValidationRequestDTO);
        assertNotNull(oAuth2ClientApplicationDTO, "Expected to be not null");
    }

    @Test
    public void testFindOAuthConsumerIfTokenIsValidWithException() throws Exception {
        when(mockedValidationHandler.findOAuthConsumerIfTokenIsValid(any(OAuth2TokenValidationRequestDTO.class)))
                .thenThrow(new IdentityOAuth2Exception("dummyException"));

        OAuth2ClientApplicationDTO oAuth2ClientApplicationDTO = tokenValidationService.findOAuthConsumerIfTokenIsValid
                (mockedTokenValidationRequestDTO);
        assertNotNull(oAuth2ClientApplicationDTO, "Expected a not null object");
        assertEquals(oAuth2ClientApplicationDTO.getAccessTokenValidationResponse().getErrorMsg(), "dummyException",
                "Expected error message did not received");
    }

    @Test
    public void testBuildIntrospectionResponse() throws Exception {
        when(mockedOAuthEventInterceptor.isEnabled()).thenReturn(true);

        when(mockedValidationHandler.buildIntrospectionResponse(any(OAuth2TokenValidationRequestDTO.class)))
                .thenReturn(mockedIntrospectionResponseDTO);

        when(mockedOAuthComponentServiceHolder.getOAuthEventInterceptorProxy()).thenReturn(mockedOAuthEventInterceptor);
        when(mockedOAuthEventInterceptor.isEnabled()).thenReturn(true, false);

        OAuth2IntrospectionResponseDTO oAuth2IntrospectionResponseDTO = tokenValidationService
                .buildIntrospectionResponse(mockedOAuth2TokenValidationRequestDTO);
        assertNotNull(oAuth2IntrospectionResponseDTO, "Expected to be not null");
    }

    @Test
    public void testBuildIntrospectionResponseWithErrorResponse() throws Exception {
        when(mockedOAuthEventInterceptor.isEnabled()).thenReturn(true);
        doThrow(new IdentityOAuth2Exception("dummyException")).when(mockedOAuthEventInterceptor).onPreTokenValidation
                (any(OAuth2TokenValidationRequestDTO.class), anyMap());

        OAuth2IntrospectionResponseDTO oAuth2IntrospectionResponseDTO = tokenValidationService
                .buildIntrospectionResponse(mockedOAuth2TokenValidationRequestDTO);
        assertNotNull(oAuth2IntrospectionResponseDTO, "Expected a not null object");
        assertEquals(oAuth2IntrospectionResponseDTO.getError(), "dummyException", "Expected error message did not received");
    }

    @Test
    public void testBuildIntrospectionResponseWithErrorResponse2() throws Exception {
        String errorMsg = "Server error occurred while building the introspection response";
        when(mockedOAuthEventInterceptor.isEnabled()).thenReturn(true);

        when(mockedValidationHandler.buildIntrospectionResponse(any(OAuth2TokenValidationRequestDTO.class)))
                .thenThrow(new IdentityOAuth2Exception("dummyException"));

        OAuth2IntrospectionResponseDTO oAuth2IntrospectionResponseDTO = tokenValidationService.buildIntrospectionResponse
                (mockedOAuth2TokenValidationRequestDTO);
        assertNotNull(oAuth2IntrospectionResponseDTO, "Expected a not null object");
        assertEquals(oAuth2IntrospectionResponseDTO.getError(), errorMsg, "Expected error message did not received");
    }

    @Test
    public void testBuildIntrospectionResponseWithPostIntrospectionValidation() throws Exception {
        when(mockedOAuthEventInterceptor.isEnabled()).thenReturn(true);

        when(mockedValidationHandler.buildIntrospectionResponse(any(OAuth2TokenValidationRequestDTO.class)))
                .thenReturn(mockedIntrospectionResponseDTO);
        when(mockedOAuthComponentServiceHolder.getOAuthEventInterceptorProxy()).thenReturn(null);

        assertNotNull(tokenValidationService.buildIntrospectionResponse(mockedOAuth2TokenValidationRequestDTO), "Expected to be not null");
    }
}
