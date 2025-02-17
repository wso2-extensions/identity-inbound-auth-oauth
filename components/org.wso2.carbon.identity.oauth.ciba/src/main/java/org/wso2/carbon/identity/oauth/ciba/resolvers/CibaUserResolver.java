package org.wso2.carbon.identity.oauth.ciba.resolvers;

import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaClientException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeRequest;

/**
 * Interface for resolving the user based on the authentication request.
 */
public interface CibaUserResolver {

    /**
     * Resolve the user based on the authentication request and returns the user’s subject identifier.
     *
     * @param cibaAuthCodeRequest Authentication request.
     * @return User’s “sub” claim.
     * @throws CibaCoreException   Error while validating the user.
     * @throws CibaClientException Error while validating the user.
     */
    String resolveUser(CibaAuthCodeRequest cibaAuthCodeRequest) throws CibaCoreException,
            CibaClientException;
}
