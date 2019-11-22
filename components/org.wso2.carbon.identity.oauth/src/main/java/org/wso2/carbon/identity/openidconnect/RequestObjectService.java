/*
 *  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.openidconnect;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.openidconnect.model.RequestedClaim;

import java.util.List;

/**
 * This class is used to invoke RequestObjectPersistenceFactory to persist and retrieve the request object in OIDC.
 */
public class RequestObjectService {

    private static final Log log = LogFactory.getLog(RequestObjectService.class);

    /**
     * To invoke the RequestObjectPersistenceFactory to insert request object.
     *
     * @param consumerKey    clientKey
     * @param sessionDataKey sessionDataKey
     * @param claims         list of claims
     * @throws RequestObjectException
     */
    public void addRequestObject(String consumerKey, String sessionDataKey, List<List<RequestedClaim>> claims)
            throws RequestObjectException {

        if (log.isDebugEnabled()) {
            log.debug("Invoking the RequestObjectPersistenceFactory to persist the request object claims against" +
                    " the sessionDataKey:" + sessionDataKey);
        }
        try {
            OAuthTokenPersistenceFactory.getInstance().getRequestObjectDAO().insertRequestObjectData
                    (consumerKey, sessionDataKey, claims);

        } catch (IdentityOAuth2Exception e) {
            log.error("Error while persisting the Request Object against sessionDataKey: " + sessionDataKey, e);
            throw new RequestObjectException(OAuth2ErrorCodes.SERVER_ERROR, "Error while processing the Request Object");
        }
    }

    /**
     * To invoke the RequestObjectPersistenceFactory to retrieve request object.
     *
     * @param sessionDataKey sessionDataKey
     * @param isUserInfo isUserInfo
     * @return list of claims which have marked as essential in the request object.
     * @throws RequestObjectException
     */
    private List<RequestedClaim> getRequestedClaimsbySessionDataKey(String sessionDataKey, boolean isUserInfo)
            throws RequestObjectException {

        List<RequestedClaim> essentialClaims;
        if (log.isDebugEnabled()) {
            log.debug("Invoking the RequestObjectPersistenceFactory to retrieve essential claims list " +
                    "by using session data key:" + sessionDataKey + ", isUserInfo: " + isUserInfo);
        }

        try {
            essentialClaims = OAuthTokenPersistenceFactory.getInstance().getRequestObjectDAO()
                    .getRequestedClaimsbySessionDataKey(sessionDataKey, isUserInfo);
        } catch (IdentityOAuth2Exception e) {
            throw new RequestObjectException(e.getMessage());
        }
        return essentialClaims;
    }

    /**
     * To invoke the RequestObjectPersistenceFactory to retrieve request object.
     *
     * @param token access token Id
     * @return list of claims which have marked as essential in the request object.
     * @throws RequestObjectException
     */
    private List<RequestedClaim> getRequestedClaims(String token, boolean isUserInfo)
            throws RequestObjectException {

        List<RequestedClaim> essentialClaims;
        if (log.isDebugEnabled()) {
            log.debug("Invoking the RequestObjectPersistenceFactory to retrieve essential claims list.");
        }

        try {
            essentialClaims = OAuthTokenPersistenceFactory.getInstance().getRequestObjectDAO()
                    .getRequestedClaims(token, isUserInfo);
        } catch (IdentityOAuth2Exception e) {
            throw new RequestObjectException(e.getMessage());
        }
        return essentialClaims;
    }

    /**
     * To invoke the RequestObjectPersistenceFactory to retrieve request object for sessionDataKey.
     *
     * @param sessionDataKey  sessionDataKey
     * @param isUserInfo  isUserInfo
     * @return list of claims which have marked as essential in the request object.
     * @throws RequestObjectException
     */
    public List<RequestedClaim> getRequestedClaimsForSessionDataKey(String sessionDataKey, boolean isUserInfo)
            throws RequestObjectException {

        return getRequestedClaimsbySessionDataKey(sessionDataKey, isUserInfo);
    }

    /**
     * To invoke the RequestObjectPersistenceFactory to retrieve request object for id_token.
     *
     * @param token  access token Id
     * @return list of claims which have marked as essential in the request object.
     * @throws RequestObjectException
     */
    public List<RequestedClaim> getRequestedClaimsForIDToken(String token) throws RequestObjectException {

        return getRequestedClaims(token, false);
    }
    /**
     * To invoke the RequestObjectPersistenceFactory to retrieve request object for id_token.
     *
     * @param token  access token Id
     * @return list of claims which have marked as essential in the request object.
     * @throws RequestObjectException
     */
    public List<RequestedClaim> getRequestedClaimsForUserInfo(String token) throws RequestObjectException {

        return getRequestedClaims(token, true);
    }

}
