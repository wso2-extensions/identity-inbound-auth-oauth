/*
 *  Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.oauth2.token;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationContext;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationRequestDTO;
import org.wso2.carbon.identity.oauth2.impersonation.services.ImpersonationMgtService;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.SubjectTokenDO;

import static org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration.JWT_TOKEN_TYPE;

/**
 * This class is used to issue subject token.
 */
public class SubjectTokenIssuer {

    public SubjectTokenDO issue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws IdentityOAuth2Exception {

        ImpersonationMgtService impersonationMgtService = OAuth2ServiceComponentHolder.getInstance()
                .getImpersonationMgtService();
        ImpersonationContext impersonationContext = impersonationMgtService.validateImpersonationRequest
                (buildImpersonationRequestDTO(oauthAuthzMsgCtx));

        if (!impersonationContext.isValidated()) {

            String client = impersonationContext.getImpersonationRequestDTO().getClientId();
            AuthenticatedUser impersonator = impersonationContext.getImpersonationRequestDTO().getImpersonator();
            String subject = impersonationContext.getImpersonationRequestDTO().getSubject();
            String errorMsg = "Impersonation request rejected for client : " + client +
                    " impersonator : " + impersonator.getLoggableMaskedUserId() + " subject : " + subject;

            if (StringUtils.isNotBlank(impersonationContext.getValidationFailureErrorCode()) ||
                    StringUtils.isNotBlank(impersonationContext.getValidationFailureErrorMessage())) {

                throw new IdentityOAuth2Exception(impersonationContext.getValidationFailureErrorCode(),
                        errorMsg + " Error Message : " + impersonationContext.getValidationFailureErrorMessage());
            }

            throw new IdentityOAuth2Exception(errorMsg);
        }

        OauthTokenIssuer oauthTokenIssuer = OAuthServerConfiguration.getInstance().getOauthTokenIssuerMap()
                .get(JWT_TOKEN_TYPE);
        SubjectTokenDO subjectTokenDO = new SubjectTokenDO();
        subjectTokenDO.setSubjectToken(oauthTokenIssuer.subjectToken(oauthAuthzMsgCtx));
        return subjectTokenDO;
    }

    private ImpersonationRequestDTO buildImpersonationRequestDTO(OAuthAuthzReqMessageContext context) {

        ImpersonationRequestDTO impersonationRequestDTO = new ImpersonationRequestDTO();
        impersonationRequestDTO.setoAuthAuthzReqMessageContext(context);
        impersonationRequestDTO.setSubject(context.getAuthorizationReqDTO().getRequestedSubjectId());
        impersonationRequestDTO.setImpersonator(context.getAuthorizationReqDTO().getUser());
        impersonationRequestDTO.setClientId(context.getAuthorizationReqDTO().getConsumerKey());
        impersonationRequestDTO.setScopes(context.getAuthorizationReqDTO().getScopes());
        impersonationRequestDTO.setTenantDomain(context.getAuthorizationReqDTO().getTenantDomain());
        return impersonationRequestDTO;
    }
}
