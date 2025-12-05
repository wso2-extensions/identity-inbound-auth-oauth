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
import org.wso2.carbon.identity.rule.evaluation.api.provider.RuleEvaluationDataProvider;

import java.util.ArrayList;
import java.util.List;

/**
 * Rule evaluation data provider for pre issue ID token flow.
 * This class provides the data required for rule evaluation in pre issue ID token flow.
 */
public class PreIssueIDTokenRuleEvaluationDataProvider implements RuleEvaluationDataProvider {

    private static final String TOKEN_REQUEST_MESSAGE_CONTEXT = "tokenReqMessageContext";
    private static final String AUTHZ_REQUEST_MESSAGE_CONTEXT = "authzReqMessageContext";
    private static final String REQUEST_TYPE = "requestType";
    private static final String REQUEST_TYPE_TOKEN = "token";
    private static final String REQUEST_TYPE_AUTHZ = "authz";
    private static final String NOT_APPLICABLE = "N/A";

    private enum RuleField {

        APPLICATION("application"),
        GRANT_TYPE("grantType");

        final String fieldName;

        RuleField(String fieldName) {

            this.fieldName = fieldName;
        }

        public String getFieldName() {

            return fieldName;
        }

        public static RuleField valueOfFieldName(String fieldName) throws RuleEvaluationDataProviderException {

            for (RuleField ruleField : RuleField.values()) {
                if (ruleField.getFieldName().equals(fieldName)) {
                    return ruleField;
                }
            }

            throw new RuleEvaluationDataProviderException("Unsupported field: " + fieldName);
        }
    }
    @Override
    public FlowType getSupportedFlowType() {

        return FlowType.PRE_ISSUE_ID_TOKEN;
    }

    @Override
    public List<FieldValue> getEvaluationData(RuleEvaluationContext ruleEvaluationContext,
                                              FlowContext flowContext, String tenantDomain)
            throws RuleEvaluationDataProviderException {

        String requestType = (String) flowContext.getContextData().get(REQUEST_TYPE);

        if (REQUEST_TYPE_TOKEN.equals(requestType)) {
            OAuthTokenReqMessageContext tokenMessageContext =
                    (OAuthTokenReqMessageContext) flowContext.getContextData()
                            .get(TOKEN_REQUEST_MESSAGE_CONTEXT);
            return getEvaluationDataForTokenRequest(ruleEvaluationContext, tokenMessageContext);
        } else if (REQUEST_TYPE_AUTHZ.equals(requestType)) {
            OAuthAuthzReqMessageContext authReqMsgCtx =
                    (OAuthAuthzReqMessageContext) flowContext.getContextData()
                            .get(AUTHZ_REQUEST_MESSAGE_CONTEXT);
            return getEvaluationDataForAuthzRequest(ruleEvaluationContext, authReqMsgCtx);
        } else {
            throw new RuleEvaluationDataProviderException("Unsupported request type: " + requestType);
        }
    }

    private List<FieldValue> getEvaluationDataForTokenRequest(RuleEvaluationContext ruleEvaluationContext,
                                                          OAuthTokenReqMessageContext tokenMessageContext)
            throws RuleEvaluationDataProviderException {

        OAuth2AccessTokenReqDTO tokenReqDTO = tokenMessageContext.getOauth2AccessTokenReqDTO();
        List<FieldValue> fieldValueList = new ArrayList<>();

        for (Field field : ruleEvaluationContext.getFields()) {
            switch (RuleField.valueOfFieldName(field.getName())) {
                case APPLICATION:
                    addApplicationFieldValue(fieldValueList, field, tokenReqDTO);
                    break;
                case GRANT_TYPE:
                    fieldValueList.add(new FieldValue(field.getName(), tokenReqDTO.getGrantType(), ValueType.STRING));
                    break;
                default:
                    throw new RuleEvaluationDataProviderException("Unsupported field: " + field.getName());
            }
        }

        return fieldValueList;
    }

    private List<FieldValue> getEvaluationDataForAuthzRequest(RuleEvaluationContext ruleEvaluationContext,
                                                              OAuthAuthzReqMessageContext authReqMsgCtx)
            throws RuleEvaluationDataProviderException {

        OAuth2AuthorizeReqDTO authzReqDTO = authReqMsgCtx.getAuthorizationReqDTO();
        List<FieldValue> fieldValueList = new ArrayList<>();

        for (Field field : ruleEvaluationContext.getFields()) {
            switch (RuleField.valueOfFieldName(field.getName())) {
                case APPLICATION:
                    addApplicationFieldValue(fieldValueList, field, authzReqDTO);
                    break;
                case GRANT_TYPE:
                    fieldValueList.add(new FieldValue(field.getName(), NOT_APPLICABLE, ValueType.STRING));
                    break;
                default:
                    throw new RuleEvaluationDataProviderException("Unsupported field: " + field.getName());
            }
        }

        return fieldValueList;
    }

    private void addApplicationFieldValue(List<FieldValue> fieldValueList, Field field,
                                          OAuth2AccessTokenReqDTO tokenReqDTO)
            throws RuleEvaluationDataProviderException {

        try {
            ServiceProvider application =
                    OAuth2Util.getServiceProvider(tokenReqDTO.getClientId(), tokenReqDTO.getTenantDomain());
            if (application != null) {
                fieldValueList.add(
                        new FieldValue(field.getName(), application.getApplicationResourceId(), ValueType.REFERENCE));
            }
        } catch (IdentityOAuth2Exception e) {
            throw new RuleEvaluationDataProviderException("Error retrieving service provider", e);
        }
    }

    private void addApplicationFieldValue(List<FieldValue> fieldValueList, Field field,
                                          OAuth2AuthorizeReqDTO authReqDTO)
            throws RuleEvaluationDataProviderException {


        try {
            ServiceProvider application =
                    OAuth2Util.getServiceProvider(authReqDTO.getConsumerKey(), authReqDTO.getTenantDomain());
            if (application != null) {
                fieldValueList.add(
                        new FieldValue(field.getName(), application.getApplicationResourceId(), ValueType.REFERENCE));
            }
        } catch (IdentityOAuth2Exception e) {
            throw new RuleEvaluationDataProviderException("Error retrieving service provider", e);
        }
    }
}
