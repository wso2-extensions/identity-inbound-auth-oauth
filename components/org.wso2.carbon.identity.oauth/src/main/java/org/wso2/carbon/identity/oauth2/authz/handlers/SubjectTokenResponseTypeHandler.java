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

package org.wso2.carbon.identity.oauth2.authz.handlers;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.authz.handlers.util.ResponseTypeHandlerUtil;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.model.SubjectTokenDO;

/**
 * The {@code SubjectTokenResponseTypeHandler} class is responsible for handling the "subject_token" response type
 * in OAuth authorization requests. It extends the {@link AbstractResponseTypeHandler} class and implements the logic
 * to issue subject tokens and build responses accordingly.
 */
public class SubjectTokenResponseTypeHandler extends AbstractResponseTypeHandler {

    private static final Log LOG = LogFactory.getLog(SubjectTokenResponseTypeHandler.class);
    private static final String SUBJECT_TOKEN = "subject_token";
    private static final String OAUTH_APP_DO = "OAuthAppDO";
    private static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";

    /**
     * This method is used to handle the response type. After authentication process finish this will redirect to the
     * constant page.
     *
     * @param oauthAuthzMsgCtx Authorization message context.
     * @return Response DTO.
     * @throws IdentityOAuth2Exception Error at device response type handler.
     */
    @Override
    public OAuth2AuthorizeRespDTO issue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws IdentityOAuth2Exception {

        OAuth2AuthorizeRespDTO respDTO = initResponse(oauthAuthzMsgCtx);
        SubjectTokenDO subjectTokenDO = OAuthComponentServiceHolder.getInstance().getOauth2Service()
                    .issueSubjectToken(oauthAuthzMsgCtx);
        String responseType = oauthAuthzMsgCtx.getAuthorizationReqDTO().getResponseType();

        // Generating id_token and generating response for id_token flow.
        if (isIDTokenIssued(responseType)) {
            ResponseTypeHandlerUtil.buildIDTokenResponseDTO(respDTO, null, oauthAuthzMsgCtx);
        }
        respDTO.setSubjectToken(subjectTokenDO.getSubjectToken());
        return respDTO;
    }

    @Override
    public boolean isAuthorizedClient(OAuthAuthzReqMessageContext authzReqMsgCtx) throws IdentityOAuth2Exception {

        OAuth2AuthorizeReqDTO authzReqDTO = authzReqMsgCtx.getAuthorizationReqDTO();
        String consumerKey = authzReqDTO.getConsumerKey();

        OAuthAppDO oAuthAppDO = (OAuthAppDO) authzReqMsgCtx.getProperty(OAUTH_APP_DO);

        String responseType = authzReqDTO.getResponseType();
        if (StringUtils.isBlank(oAuthAppDO.getGrantTypes())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Could not find authorized grant types for subject token response type" +
                        " for client id: " + consumerKey);
            }
            return false;
        }
        if (!oAuthAppDO.getGrantTypes().contains(TOKEN_EXCHANGE)) {
            LOG.error("Unable to handle subject token response type. Token exchange Grant Type is not " +
                    "enabled for client id: " + consumerKey);
            return false;
        }
        if (oAuthAppDO.isSubjectTokenEnabled() && StringUtils.contains(responseType, SUBJECT_TOKEN)) {
            authzReqMsgCtx.setSubjectTokenFlow(true);
            return true;
        }
        return false;
    }

    private boolean isIDTokenIssued(String responseType) {

        return StringUtils.contains(responseType, OAuthConstants.ID_TOKEN);
    }
}
