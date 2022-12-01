/*
 * Copyright (c) 2022, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.token.handlers.response;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.Map;

/**
 * This interface needs to be implemented if there are access token response modification requirements.
 */
public interface AccessTokenResponseHandler {

    /**
     * Returns additional token response attributes to be added to the access token response.
     *
     * @param tokReqMsgCtx {@link OAuthTokenReqMessageContext} token request message context.
     * @return Map of additional attributes to be added.
     * @throws IdentityOAuth2Exception Error while constructing additional token response attributes.
     */
    Map<String, Object> getAdditionalTokenResponseAttributes(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception;
}
