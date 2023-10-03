package org.wso2.carbon.identity.oauth.handler;

import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

/**
 * Token persistence handler interface used to abstract the token persistence logic.
 * {@link DefaultIndirectTokenRevocationHandlerImpl} is used to preserve the existing token persistence behaviour.
 * An extension can be used to remove or modify the token persistence behaviour.
 */
public interface IndirectTokenRevocationHandler {

    public boolean revokeTokens(String username, UserStoreManager userStoreManager)
            throws UserStoreException;
}
