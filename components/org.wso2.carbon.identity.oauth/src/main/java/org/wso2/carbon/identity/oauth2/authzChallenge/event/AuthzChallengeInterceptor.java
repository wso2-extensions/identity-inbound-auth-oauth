package org.wso2.carbon.identity.oauth2.authzChallenge.event;

import org.wso2.carbon.identity.core.handler.IdentityHandler;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthzChallengeReqDTO;


public interface AuthzChallengeInterceptor extends IdentityHandler {

    default String handleAuthzChallengeReq(OAuth2AuthzChallengeReqDTO requestDTO) throws IdentityOAuth2Exception {

        return "";
    }
}
