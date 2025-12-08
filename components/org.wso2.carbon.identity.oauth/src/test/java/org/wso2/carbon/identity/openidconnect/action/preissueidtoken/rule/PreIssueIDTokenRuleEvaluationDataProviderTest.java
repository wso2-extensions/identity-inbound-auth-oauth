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

package org.wso2.carbon.identity.openidconnect.action.preissueidtoken.rule;

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.rule.evaluation.api.exception.RuleEvaluationDataProviderException;
import org.wso2.carbon.identity.rule.evaluation.api.model.Field;
import org.wso2.carbon.identity.rule.evaluation.api.model.FieldValue;
import org.wso2.carbon.identity.rule.evaluation.api.model.FlowContext;
import org.wso2.carbon.identity.rule.evaluation.api.model.FlowType;
import org.wso2.carbon.identity.rule.evaluation.api.model.RuleEvaluationContext;
import org.wso2.carbon.identity.rule.evaluation.api.model.ValueType;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

public class PreIssueIDTokenRuleEvaluationDataProviderTest {

    @InjectMocks
    private PreIssueIDTokenRuleEvaluationDataProvider provider;
    @Mock
    private OAuthTokenReqMessageContext tokenMessageContext;
    @Mock
    private OAuthAuthzReqMessageContext authzReqMessageContext;
    @Mock
    private OAuth2AccessTokenReqDTO tokenReqDTO;
    @Mock
    private OAuth2AuthorizeReqDTO authzReqDTO;
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
        oAuth2UtilMockedStatic = mockStatic(OAuth2Util.class);
    }

    @AfterMethod
    public void tearDown() {

        oAuth2UtilMockedStatic.close();
    }

    @Test
    public void testGetSupportedFlowType() {

        assertEquals(provider.getSupportedFlowType(), FlowType.PRE_ISSUE_ID_TOKEN);
    }

    @Test
    public void testGetEvaluationDataForTokenRequestWithValidFields() throws Exception {

        // Setup token request context
        Map<String, Object> contextData = new HashMap<>();
        contextData.put("requestType", "token");
        contextData.put("tokenReqMessageContext", tokenMessageContext);
        when(flowContext.getContextData()).thenReturn(contextData);
        when(tokenMessageContext.getOauth2AccessTokenReqDTO()).thenReturn(tokenReqDTO);

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

    @Test
    public void testGetEvaluationDataForAuthzRequestWithValidFields() throws Exception {

        // Setup authz request context
        Map<String, Object> contextData = new HashMap<>();
        contextData.put("requestType", "authz");
        contextData.put("authzReqMessageContext", authzReqMessageContext);
        when(flowContext.getContextData()).thenReturn(contextData);
        when(authzReqMessageContext.getAuthorizationReqDTO()).thenReturn(authzReqDTO);

        Field applicationField = new Field("application", ValueType.REFERENCE);
        Field grantTypeField = new Field("grantType", ValueType.STRING);
        when(ruleEvaluationContext.getFields()).thenReturn(Arrays.asList(applicationField, grantTypeField));

        when(authzReqDTO.getConsumerKey()).thenReturn("consumerKey");
        when(authzReqDTO.getTenantDomain()).thenReturn("tenantDomain");

        when(OAuth2Util.getServiceProvider(anyString(), anyString())).thenReturn(serviceProvider);
        when(serviceProvider.getApplicationResourceId()).thenReturn("testapp");

        List<FieldValue> fieldValues = provider.getEvaluationData(ruleEvaluationContext, flowContext, null);

        assertEquals(fieldValues.size(), 2);
        assertEquals(fieldValues.get(0).getName(), "application");
        assertEquals(fieldValues.get(0).getValue(), "testapp");
        assertEquals(fieldValues.get(1).getName(), "grantType");
        assertEquals(fieldValues.get(1).getValue(), "N/A");
    }

    @Test(expectedExceptions = RuleEvaluationDataProviderException.class, expectedExceptionsMessageRegExp =
            "Unsupported field: unsupported")
    public void testGetEvaluationDataForTokenRequestWithUnsupportedField() throws Exception {

        // Setup token request context
        Map<String, Object> contextData = new HashMap<>();
        contextData.put("requestType", "token");
        contextData.put("tokenReqMessageContext", tokenMessageContext);
        when(flowContext.getContextData()).thenReturn(contextData);
        when(tokenMessageContext.getOauth2AccessTokenReqDTO()).thenReturn(tokenReqDTO);

        Field unsupportedField = new Field("unsupported", ValueType.STRING);
        when(ruleEvaluationContext.getFields()).thenReturn(Collections.singletonList(unsupportedField));

        provider.getEvaluationData(ruleEvaluationContext, flowContext, null);
    }

    @Test(expectedExceptions = RuleEvaluationDataProviderException.class, expectedExceptionsMessageRegExp =
            "Unsupported field: unsupported")
    public void testGetEvaluationDataForAuthzRequestWithUnsupportedField() throws Exception {

        // Setup authz request context
        Map<String, Object> contextData = new HashMap<>();
        contextData.put("requestType", "authz");
        contextData.put("authzReqMessageContext", authzReqMessageContext);
        when(flowContext.getContextData()).thenReturn(contextData);
        when(authzReqMessageContext.getAuthorizationReqDTO()).thenReturn(authzReqDTO);

        Field unsupportedField = new Field("unsupported", ValueType.STRING);
        when(ruleEvaluationContext.getFields()).thenReturn(Collections.singletonList(unsupportedField));

        provider.getEvaluationData(ruleEvaluationContext, flowContext, null);
    }

    @Test(expectedExceptions = RuleEvaluationDataProviderException.class)
    public void testGetEvaluationDataForTokenRequestWhenRetrievingServiceProviderFails() throws Exception {

        // Setup token request context
        Map<String, Object> contextData = new HashMap<>();
        contextData.put("requestType", "token");
        contextData.put("tokenReqMessageContext", tokenMessageContext);
        when(flowContext.getContextData()).thenReturn(contextData);
        when(tokenMessageContext.getOauth2AccessTokenReqDTO()).thenReturn(tokenReqDTO);

        Field applicationField = new Field("application", ValueType.REFERENCE);
        when(ruleEvaluationContext.getFields()).thenReturn(Collections.singletonList(applicationField));

        when(tokenReqDTO.getClientId()).thenReturn("clientId");
        when(tokenReqDTO.getTenantDomain()).thenReturn("tenantDomain");

        when(OAuth2Util.getServiceProvider(anyString(), anyString())).thenThrow(new IdentityOAuth2Exception("Error"));

        provider.getEvaluationData(ruleEvaluationContext, flowContext, "tenantDomain");
    }

    @Test(expectedExceptions = RuleEvaluationDataProviderException.class)
    public void testGetEvaluationDataForAuthzRequestWhenRetrievingServiceProviderFails() throws Exception {

        // Setup authz request context
        Map<String, Object> contextData = new HashMap<>();
        contextData.put("requestType", "authz");
        contextData.put("authzReqMessageContext", authzReqMessageContext);
        when(flowContext.getContextData()).thenReturn(contextData);
        when(authzReqMessageContext.getAuthorizationReqDTO()).thenReturn(authzReqDTO);

        Field applicationField = new Field("application", ValueType.REFERENCE);
        when(ruleEvaluationContext.getFields()).thenReturn(Collections.singletonList(applicationField));

        when(authzReqDTO.getConsumerKey()).thenReturn("consumerKey");
        when(authzReqDTO.getTenantDomain()).thenReturn("tenantDomain");

        when(OAuth2Util.getServiceProvider(anyString(), anyString())).thenThrow(new IdentityOAuth2Exception("Error"));

        provider.getEvaluationData(ruleEvaluationContext, flowContext, "tenantDomain");
    }

    @Test(expectedExceptions = RuleEvaluationDataProviderException.class, expectedExceptionsMessageRegExp =
            "Unsupported request type: unknown")
    public void testGetEvaluationDataWithUnsupportedRequestType() throws Exception {

        Map<String, Object> contextData = new HashMap<>();
        contextData.put("requestType", "unknown");
        when(flowContext.getContextData()).thenReturn(contextData);

        provider.getEvaluationData(ruleEvaluationContext, flowContext, null);
    }

    @Test
    public void testGetEvaluationDataForTokenRequestWithNullServiceProvider() throws Exception {

        // Setup token request context
        Map<String, Object> contextData = new HashMap<>();
        contextData.put("requestType", "token");
        contextData.put("tokenReqMessageContext", tokenMessageContext);
        when(flowContext.getContextData()).thenReturn(contextData);
        when(tokenMessageContext.getOauth2AccessTokenReqDTO()).thenReturn(tokenReqDTO);

        Field applicationField = new Field("application", ValueType.REFERENCE);
        Field grantTypeField = new Field("grantType", ValueType.STRING);
        when(ruleEvaluationContext.getFields()).thenReturn(Arrays.asList(applicationField, grantTypeField));

        when(tokenReqDTO.getClientId()).thenReturn("clientId");
        when(tokenReqDTO.getTenantDomain()).thenReturn("tenantDomain");
        when(tokenReqDTO.getGrantType()).thenReturn("client_credentials");

        when(OAuth2Util.getServiceProvider(anyString(), anyString())).thenReturn(null);

        List<FieldValue> fieldValues = provider.getEvaluationData(ruleEvaluationContext, flowContext, null);

        // Should only have grantType field, not application field since service provider is null
        assertEquals(fieldValues.size(), 1);
        assertEquals(fieldValues.get(0).getName(), "grantType");
        assertEquals(fieldValues.get(0).getValue(), "client_credentials");
    }

    @Test
    public void testGetEvaluationDataForAuthzRequestWithNullServiceProvider() throws Exception {

        // Setup authz request context
        Map<String, Object> contextData = new HashMap<>();
        contextData.put("requestType", "authz");
        contextData.put("authzReqMessageContext", authzReqMessageContext);
        when(flowContext.getContextData()).thenReturn(contextData);
        when(authzReqMessageContext.getAuthorizationReqDTO()).thenReturn(authzReqDTO);

        Field applicationField = new Field("application", ValueType.REFERENCE);
        Field grantTypeField = new Field("grantType", ValueType.STRING);
        when(ruleEvaluationContext.getFields()).thenReturn(Arrays.asList(applicationField, grantTypeField));

        when(authzReqDTO.getConsumerKey()).thenReturn("consumerKey");
        when(authzReqDTO.getTenantDomain()).thenReturn("tenantDomain");

        when(OAuth2Util.getServiceProvider(anyString(), anyString())).thenReturn(null);

        List<FieldValue> fieldValues = provider.getEvaluationData(ruleEvaluationContext, flowContext, null);

        // Should only have grantType field, not application field since service provider is null
        assertEquals(fieldValues.size(), 1);
        assertEquals(fieldValues.get(0).getName(), "grantType");
        assertEquals(fieldValues.get(0).getValue(), "N/A");
    }
}
