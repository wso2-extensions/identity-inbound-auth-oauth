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
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationContext;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationRequestDTO;
import org.wso2.carbon.identity.oauth2.impersonation.services.ImpersonationMgtService;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.SubjectTokenDO;
import org.wso2.carbon.utils.DiagnosticLog;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCConfigProperties.SUBJECT_TOKEN_EXPIRY_TIME_VALUE;
import static org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration.JWT_TOKEN_TYPE;

/**
 * The {@code SubjectTokenIssuer} class is responsible for issuing subject tokens for OAuth authorization requests
 * with impersonation. It validates impersonation requests and issues subject tokens based on the provided context.
 */
public class SubjectTokenIssuer {

    private static final String OAUTH_APP_DO = "OAuthAppDO";

    /**
     * Issues a subject token for the given OAuth authorization request message context.
     *
     * @param oauthAuthzMsgCtx the OAuth authorization request message context
     * @return the subject token data object containing the issued subject token
     * @throws IdentityOAuth2Exception if an error occurs during subject token issuance
     */
    public SubjectTokenDO issue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws IdentityOAuth2Exception {

        // Validate impersonation request
        ImpersonationMgtService impersonationMgtService = OAuth2ServiceComponentHolder.getInstance()
                .getImpersonationMgtService();
        ImpersonationContext impersonationContext = impersonationMgtService.validateImpersonationRequest(
                buildImpersonationRequestDTO(oauthAuthzMsgCtx));

        // If impersonation request is not validated, throw an exception
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

        // Issue subject token using OAuth token issuer
        OauthTokenIssuer oauthTokenIssuer = OAuthServerConfiguration.getInstance().getOauthTokenIssuerMap()
                .get(JWT_TOKEN_TYPE);
        SubjectTokenDO subjectTokenDO = new SubjectTokenDO();
        subjectTokenDO.setSubjectToken(oauthTokenIssuer.issueSubjectToken(oauthAuthzMsgCtx));
        OAuthAppDO oAuthAppDO = (OAuthAppDO) oauthAuthzMsgCtx.getProperty(OAUTH_APP_DO);
        int subjectTokenLifeTime = oAuthAppDO.getSubjectTokenExpiryTime() <= 0 ? SUBJECT_TOKEN_EXPIRY_TIME_VALUE :
                oAuthAppDO.getSubjectTokenExpiryTime();

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.ISSUE_SUBJECT_TOKEN);
            diagnosticLogBuilder.inputParam(LogConstants.InputKeys.CLIENT_ID,
                            oauthAuthzMsgCtx.getAuthorizationReqDTO().getConsumerKey())
                    .inputParam(OAuthConstants.LogConstants.InputKeys.AUTHORIZED_SCOPES,
                            oauthAuthzMsgCtx.getApprovedScope())
                    .inputParam(OAuthConstants.LogConstants.InputKeys.RESPONSE_TYPE,
                            oauthAuthzMsgCtx.getAuthorizationReqDTO().getResponseType())
                    .inputParam("token expiry time (s)", subjectTokenLifeTime)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .resultMessage("Subject token issued for the application.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);

            AuthenticatedUser impersonator = oauthAuthzMsgCtx.getAuthorizationReqDTO().getUser();
            if (impersonator != null) {
                try {
                    diagnosticLogBuilder.inputParam(LogConstants.InputKeys.USER_ID, impersonator.getUserId());
                } catch (UserIdNotFoundException e) {
                    if (StringUtils.isNotBlank(impersonator.getAuthenticatedSubjectIdentifier())) {
                        diagnosticLogBuilder.inputParam(LogConstants.InputKeys.USER, LoggerUtils.isLogMaskingEnable ?
                                LoggerUtils.getMaskedContent(impersonator.getAuthenticatedSubjectIdentifier()) :
                                impersonator.getAuthenticatedSubjectIdentifier());
                    }
                }
            }
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        return subjectTokenDO;
    }

    /**
     * Builds an impersonation request DTO based on the provided OAuth authorization request message context.
     *
     * @param context the OAuth authorization request message context
     * @return the impersonation request DTO containing information about the impersonation request
     */
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
