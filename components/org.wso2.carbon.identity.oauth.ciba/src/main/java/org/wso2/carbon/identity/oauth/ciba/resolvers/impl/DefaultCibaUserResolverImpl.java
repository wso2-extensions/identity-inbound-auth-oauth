/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.ciba.resolvers.impl;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.multi.attribute.login.mgt.ResolvedUserResult;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaClientException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.internal.CibaServiceComponentHolder;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeRequest;
import org.wso2.carbon.identity.oauth.ciba.resolvers.CibaUserResolver;
import org.wso2.carbon.user.core.common.User;

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

    @Override
    public User getUser(String userLoginIdentifier, String tenantDomain) throws CibaCoreException, CibaClientException {

        ResolvedUserResult resolvedUserResult = CibaServiceComponentHolder.getMultiAttributeLoginService()
                .resolveUser(userLoginIdentifier, tenantDomain);
        if (resolvedUserResult.getResolvedStatus() == ResolvedUserResult.UserResolvedStatus.SUCCESS) {
            User user = resolvedUserResult.getUser();
            if (user != null) {
                return user;
            } else {
                throw new CibaCoreException("Unable to resolve user from the login identifier.");
            }
        } else {
            throw new CibaClientException("Invalid user login hint.");
        }
    }
}
