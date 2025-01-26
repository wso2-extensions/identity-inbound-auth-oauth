/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth.action.rule;

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.rule.evaluation.exception.RuleEvaluationDataProviderException;
import org.wso2.carbon.identity.rule.evaluation.model.Field;
import org.wso2.carbon.identity.rule.evaluation.model.FieldValue;
import org.wso2.carbon.identity.rule.evaluation.model.FlowContext;
import org.wso2.carbon.identity.rule.evaluation.model.FlowType;
import org.wso2.carbon.identity.rule.evaluation.model.RuleEvaluationContext;
import org.wso2.carbon.identity.rule.evaluation.model.ValueType;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

public class PreIssueAccessTokenRuleEvaluationDataProviderTest {

    @InjectMocks
    private PreIssueAccessTokenRuleEvaluationDataProvider provider;
    @Mock
    private OAuthTokenReqMessageContext tokenMessageContext;
    @Mock
    private OAuth2AccessTokenReqDTO tokenReqDTO;
    @Mock
    private FlowContext flowContext;
    @Mock
    private RuleEvaluationContext ruleEvaluationContext;
    @Mock
    private ServiceProvider serviceProvider;
    private MockedStatic<OAuth2Util> oAuth2UtilMockedStatic;

    @BeforeMethod
    public void setUp() {

        MockitoAnnotations.openMocks(this);
        when(flowContext.getContextData()).thenReturn(
                Collections.singletonMap("tokenMessageContext", tokenMessageContext));
        when(tokenMessageContext.getOauth2AccessTokenReqDTO()).thenReturn(tokenReqDTO);

        oAuth2UtilMockedStatic = mockStatic(OAuth2Util.class);
    }

    @AfterMethod
    public void tearDown() {

        oAuth2UtilMockedStatic.close();
    }

    @Test
    public void testGetSupportedFlowType() {

        assertEquals(provider.getSupportedFlowType(), FlowType.PRE_ISSUE_ACCESS_TOKEN);
    }

    @Test
    public void testGetEvaluationDataWithValidFields() throws Exception {

        Field applicationField = new Field("application", ValueType.REFERENCE);
        Field grantTypeField = new Field("grantType", ValueType.STRING);
        when(ruleEvaluationContext.getFields()).thenReturn(Arrays.asList(applicationField, grantTypeField));

        when(tokenReqDTO.getClientId()).thenReturn("clientId");
        when(tokenReqDTO.getTenantDomain()).thenReturn("tenantDomain");
        when(tokenReqDTO.getGrantType()).thenReturn("authorization_code");

        when(OAuth2Util.getServiceProvider(anyString(), anyString())).thenReturn(serviceProvider);
        when(serviceProvider.getApplicationResourceId()).thenReturn("testapp");

        List<FieldValue> fieldValues = provider.getEvaluationData(ruleEvaluationContext, flowContext, null);

        assertEquals(fieldValues.size(), 2);
        assertEquals(fieldValues.get(0).getName(), "application");
        assertEquals(fieldValues.get(0).getValue(), "testapp");
        assertEquals(fieldValues.get(1).getName(), "grantType");
        assertEquals(fieldValues.get(1).getValue(), "authorization_code");
    }

    @Test(expectedExceptions = RuleEvaluationDataProviderException.class, expectedExceptionsMessageRegExp =
            "Unsupported field: unsupported")
    public void testGetEvaluationDataWithUnsupportedField() throws Exception {

        Field unsupportedField = new Field("unsupported", ValueType.STRING);
        when(ruleEvaluationContext.getFields()).thenReturn(Collections.singletonList(unsupportedField));

        provider.getEvaluationData(ruleEvaluationContext, flowContext, null);
    }

    @Test(expectedExceptions = RuleEvaluationDataProviderException.class)
    public void testGetEvaluationDataWhenRetrievingServiceProviderFails() throws Exception {

        Field applicationField = new Field("application", ValueType.REFERENCE);
        when(ruleEvaluationContext.getFields()).thenReturn(Collections.singletonList(applicationField));

        when(tokenReqDTO.getClientId()).thenReturn("clientId");
        when(tokenReqDTO.getTenantDomain()).thenReturn("tenantDomain");

        when(OAuth2Util.getServiceProvider(anyString(), anyString())).thenThrow(new IdentityOAuth2Exception("Error"));

        provider.getEvaluationData(ruleEvaluationContext, flowContext, "tenantDomain");
    }
}
