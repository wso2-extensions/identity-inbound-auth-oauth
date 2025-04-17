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

package org.wso2.carbon.identity.oauth2.token;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationContext;
import org.wso2.carbon.identity.oauth2.impersonation.services.ImpersonationMgtServiceImpl;
import org.wso2.carbon.identity.oauth2.impersonation.validators.ImpersonationValidator;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.SubjectTokenDO;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration.JWT_TOKEN_TYPE;

/**
 * Unit test cases for {@link SubjectTokenIssuer}
 */
@Listeners(MockitoTestNGListener.class)
public class SubjectTokenIssuerTest {
    @Mock
    private OAuthServerConfiguration mockOAuthServerConfiguration;
    @Mock
    private AuthenticatedUser impersonator;
    @Mock
    private OAuth2AuthorizeReqDTO oAuth2AuthorizeReqDTO;
    @Mock
    private OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext;
    @Mock
    private JWTTokenIssuer jwtTokenIssuer;
    private static final String[] SCOPES_WITHOUT_OPENID = new String[]{"scope1", "scope2"};
    private static final String OAUTH_APP_DO = "OAuthAppDO";
    private ImpersonationMgtServiceImpl impersonationMgtService = new ImpersonationMgtServiceImpl();

    private MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration;
    private MockedStatic<LoggerUtils> loggerUtils;

    @BeforeMethod
    public void setUp() throws Exception {

        oAuthServerConfiguration = mockStatic(OAuthServerConfiguration.class);
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
        OAuth2ServiceComponentHolder.getInstance().setImpersonationMgtService(impersonationMgtService);

        lenient().when(impersonator.getLoggableMaskedUserId()).thenReturn("123456789");

        when(oAuth2AuthorizeReqDTO.getRequestedSubjectId()).thenReturn("dummySubjectId");
        when(oAuth2AuthorizeReqDTO.getUser()).thenReturn(impersonator);
        when(oAuth2AuthorizeReqDTO.getConsumerKey()).thenReturn("dummyConsumerKey");
        when(oAuth2AuthorizeReqDTO.getScopes()).thenReturn(SCOPES_WITHOUT_OPENID);
        when(oAuth2AuthorizeReqDTO.getTenantDomain()).thenReturn("carbon.super");

        lenient().when(jwtTokenIssuer.issueSubjectToken(oAuthAuthzReqMessageContext)).thenReturn("dummySubjectToken");
        Map<String, OauthTokenIssuer> oauthTokenIssuerMap = new HashMap<>();
        oauthTokenIssuerMap.put(JWT_TOKEN_TYPE, jwtTokenIssuer);
        lenient().when(mockOAuthServerConfiguration.getOauthTokenIssuerMap()).thenReturn(oauthTokenIssuerMap);
        loggerUtils = mockStatic(LoggerUtils.class);
        loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
    }

    @AfterMethod
    public void tearDown() {
        // Validator is removed based on the class name.
        OAuth2ServiceComponentHolder.getInstance()
                .removeImpersonationValidator(new DummyErrornusImpersonationValidator());
        oAuthServerConfiguration.close();
        loggerUtils.close();
    }

    @Test
    public void testIssue() throws IdentityException {

        when(oAuthAuthzReqMessageContext.getAuthorizationReqDTO()).thenReturn(oAuth2AuthorizeReqDTO);
        when(oAuthAuthzReqMessageContext.getProperty(OAUTH_APP_DO)).thenReturn(new OAuthAppDO());
        OAuth2ServiceComponentHolder.getInstance().addImpersonationValidator(
                new DummyImpersonationValidator());

        SubjectTokenIssuer subjectTokenIssuer = new SubjectTokenIssuer();
        SubjectTokenDO subjectTokenDO = subjectTokenIssuer.issue(oAuthAuthzReqMessageContext);

        assertNotNull(subjectTokenDO.getSubjectToken(), "Subject token is null");

    }

    static class DummyImpersonationValidator implements ImpersonationValidator {

        @Override
        public int getPriority() {

            return 100;
        }

        @Override
        public String getImpersonationValidatorName() {

            return "dummyImpersonationValidators";
        }

        @Override
        public ImpersonationContext validateImpersonation(ImpersonationContext impersonationContext)
                throws IdentityOAuth2Exception {

            impersonationContext.setValidated(true);
            return impersonationContext;
        }
    }

    @Test
    public void testIssueNegativeCase() {

        try {
            when(oAuthAuthzReqMessageContext.getAuthorizationReqDTO()).thenReturn(oAuth2AuthorizeReqDTO);
            OAuth2ServiceComponentHolder.getInstance().addImpersonationValidator(
                    new DummyErrornusImpersonationValidator());

            SubjectTokenIssuer subjectTokenIssuer = new SubjectTokenIssuer();
            subjectTokenIssuer.issue(oAuthAuthzReqMessageContext);
        } catch (IdentityOAuth2Exception e) {
            assertEquals(e.getErrorCode(), "ERR_60001", "Expected error code is different");
            assertEquals(e.getMessage(), "Impersonation request rejected for client : " +
                    "dummyConsumerKey impersonator : 123456789 subject : dummySubjectId Error Message : " +
                    "Test Error Message", "Expected error msg is different");
        }
    }

    static class DummyErrornusImpersonationValidator implements ImpersonationValidator {

        @Override
        public int getPriority() {

            return 100;
        }

        @Override
        public String getImpersonationValidatorName() {

            return "dummyErrornusImpersonationValidator";
        }

        @Override
        public ImpersonationContext validateImpersonation(ImpersonationContext impersonationContext)
                throws IdentityOAuth2Exception {

            impersonationContext.setValidated(false);
            impersonationContext.setValidationFailureErrorCode("ERR_60001");
            impersonationContext.setValidationFailureErrorMessage("Test Error Message");
            return impersonationContext;
        }
    }
}
