package org.wso2.carbon.identity.oauth2.authzChallenge.event;

import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthzChallengeReqDTO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

public class AbstractAuthzChallengeInterceptor extends AbstractIdentityHandler implements AuthzChallengeInterceptor {

    @Override
    public void handleAuthzChallengeReq(OAuth2AuthzChallengeReqDTO requestDTO) throws IdentityOAuth2Exception {
        // Nothing to implement
    }

    public boolean isEnabled() {
        IdentityEventListenerConfig identityEventListenerConfig = IdentityUtil.readEventListenerProperty(AbstractIdentityHandler.class.getName(), this.getClass().getName());
        return identityEventListenerConfig == null ? true : Boolean.parseBoolean(identityEventListenerConfig.getEnable());
    }

}
