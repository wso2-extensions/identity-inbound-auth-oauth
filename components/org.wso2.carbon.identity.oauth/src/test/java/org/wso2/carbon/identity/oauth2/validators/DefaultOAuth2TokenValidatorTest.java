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

import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;

import java.util.HashSet;
import java.util.Set;

import static org.powermock.api.mockito.PowerMockito.mock;

@WithCarbonHome
public class DefaultOAuth2TokenValidatorTest {

    private DefaultOAuth2TokenValidator defaultOAuth2TokenValidator;
    private OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO;
    private OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO;
    private OAuth2TokenValidationMessageContext oAuth2TokenValidationMessageContext;

    @BeforeMethod
    public void setUp() throws Exception {
        defaultOAuth2TokenValidator = new DefaultOAuth2TokenValidator();
        oAuth2TokenValidationRequestDTO = new OAuth2TokenValidationRequestDTO();
        OAuth2TokenValidationRequestDTO.TokenValidationContextParam tokenValidationContextParam = mock(OAuth2TokenValidationRequestDTO.TokenValidationContextParam.class);
        tokenValidationContextParam.setKey("sampleKey");
        tokenValidationContextParam.setValue("sampleValue");

        OAuth2TokenValidationRequestDTO.TokenValidationContextParam[] tokenValidationContextParams = {tokenValidationContextParam};
        oAuth2TokenValidationRequestDTO.setContext(tokenValidationContextParams);
        oAuth2TokenValidationResponseDTO = new OAuth2TokenValidationResponseDTO();
        oAuth2TokenValidationMessageContext =
                new OAuth2TokenValidationMessageContext
                        (oAuth2TokenValidationRequestDTO, oAuth2TokenValidationResponseDTO);
    }

    @AfterMethod
    public void tearDown() throws Exception {
    }

    @Test
    public void testValidateAccessDelegation() throws Exception {
        Assert.assertTrue(defaultOAuth2TokenValidator
                .validateAccessDelegation(oAuth2TokenValidationMessageContext));
    }

    @Test
    public void testValidateScope() throws Exception {

        String scopeValidatorClazz
                = "org.wso2.carbon.identity.oauth2.validators.sample.validators.SampleScopeValidator";
        OAuthServerConfiguration oAuthServerConfiguration = OAuthServerConfiguration.getInstance();
        if (scopeValidatorClazz != null) {
            OAuth2ScopeValidator scopeValidator
                    = getClassInstance(scopeValidatorClazz, OAuth2ScopeValidator.class);
            Set<OAuth2ScopeValidator> oAuth2ScopeValidators = new HashSet<OAuth2ScopeValidator>();
            oAuth2ScopeValidators.add(scopeValidator);

            oAuthServerConfiguration.setOAuth2ScopeValidators(oAuth2ScopeValidators);
        }
        Assert.assertTrue(defaultOAuth2TokenValidator
                .validateScope(oAuth2TokenValidationMessageContext), "Access token validated");
    }

    @Test
    public void testValidateAccessToken() throws Exception {
        Assert.assertTrue(defaultOAuth2TokenValidator
                .validateAccessToken(oAuth2TokenValidationMessageContext));
    }

    private <T> T getClassInstance(String scopeValidatorClazz, Class<T> type)
            throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        Class clazz = Thread.currentThread().getContextClassLoader().loadClass(scopeValidatorClazz);
        return type.cast(clazz.newInstance());
    }
}
