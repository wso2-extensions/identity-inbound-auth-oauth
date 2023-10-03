package org.wso2.carbon.identity.oauth.handler;

import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

/**
 * Default implementation of {@link IndirectTokenRevocationHandler}
 */
public class DefaultIndirectTokenRevocationHandlerImpl implements IndirectTokenRevocationHandler {

    @Override
    public boolean revokeTokens(String username, UserStoreManager userStoreManager)
            throws UserStoreException {

        return OAuthUtil.revokeTokens(username, userStoreManager);
    }
}
