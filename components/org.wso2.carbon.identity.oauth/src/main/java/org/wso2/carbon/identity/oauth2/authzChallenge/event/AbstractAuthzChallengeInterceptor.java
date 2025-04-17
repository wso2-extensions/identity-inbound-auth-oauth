/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.authzChallenge.event;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthzChallengeReqDTO;

public class AbstractAuthzChallengeInterceptor extends AbstractIdentityHandler implements AuthzChallengeInterceptor {

    /**
     * Handle the authorization challenge request and extract the DPoP thumbprint.
     * This default implementation returns {@code StringUtils.EMPTY}, indicating no thumbprint was extracted.
     * Implementations should override this method to provide specific extraction logic.
     *
     * @param requestDTO Authorization challenge request DTO containing necessary request context.
     * @return Extracted thumbprint as a {@link String}, or {@code StringUtils.EMPTY} if not applicable.
     * @throws IdentityOAuth2Exception
     */
    @Override
    public String handleAuthzChallengeReq(OAuth2AuthzChallengeReqDTO requestDTO) throws IdentityOAuth2Exception {

        return StringUtils.EMPTY;
    }

    public boolean isEnabled() {

        IdentityEventListenerConfig identityEventListenerConfig = IdentityUtil
                .readEventListenerProperty(AbstractIdentityHandler.class.getName(), this.getClass().getName());
        return identityEventListenerConfig == null ? true :
                Boolean.parseBoolean(identityEventListenerConfig.getEnable());
    }

}
