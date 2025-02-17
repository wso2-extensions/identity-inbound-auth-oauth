package org.wso2.carbon.identity.oauth.ciba.resolvers.impl;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaClientException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeRequest;
import org.wso2.carbon.identity.oauth.ciba.resolvers.CibaUserResolver;

/**
 * Default implementation of the CibaUserResolver interface.
 */
public class DefaultCibaUserResolverImpl implements CibaUserResolver {

    private static final Log log = LogFactory.getLog(DefaultCibaUserResolverImpl.class);

    @Override
    public String resolveUser(CibaAuthCodeRequest cibaAuthCodeRequest) throws CibaCoreException,
            CibaClientException {

        if (log.isDebugEnabled()) {
            log.debug("Validating the user for the authentication request.");
        }
        String userHint = cibaAuthCodeRequest.getUserHint();
        if (StringUtils.isBlank(userHint)) {
            throw new CibaClientException("User hint is not provided in the authentication request.");
        }

        return cibaAuthCodeRequest.getUserHint();
    }

}
