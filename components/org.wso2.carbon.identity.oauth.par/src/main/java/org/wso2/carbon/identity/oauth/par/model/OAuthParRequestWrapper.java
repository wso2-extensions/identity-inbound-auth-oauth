/**
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com). All Rights Reserved.
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
package org.wso2.carbon.identity.oauth.par.model;


import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthRequestException;
import org.wso2.carbon.identity.oauth.par.dao.ParDAOFactory;

import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * Wrap class to handle PAR request.
 */
public class OAuthParRequestWrapper extends HttpServletRequestWrapper {

    HashMap<String, String> params = new HashMap<>();

    public OAuthParRequestWrapper(HttpServletRequest request) throws Exception {
        super(request);

        // Get request data from PAR and add to params
        String requestUri = request.getParameter(OAuthConstants.OAuth20Params.REQUEST_URI);
        String uuid = requestUri.substring(requestUri.length() - 36);

        //get data from Database
        if (!uuid.isEmpty()) {
            ParDataRecord record = ParDAOFactory.getInstance().getParAuthMgtDAO().getParRequestRecord(uuid);
            params = record.getParamMap();
        } else {
            throw new InvalidOAuthRequestException("Request URI is empty in the authorization request",
                    OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ErrorCodes.OAuth2SubErrorCodes.INVALID_REQUEST_URI);
        }

    }

    @Override
    public String getParameter(String name) {

        if (params.containsKey(name)) {
            return params.get(name);
        }

        return super.getParameter(name);
    }
}
