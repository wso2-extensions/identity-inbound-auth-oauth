/**
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
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


import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.par.common.ParConstants;
import org.wso2.carbon.identity.oauth.par.core.ParAuthService;
import org.wso2.carbon.identity.oauth.par.exceptions.ParAuthFailureException;
import org.wso2.carbon.identity.oauth.par.exceptions.ParCoreException;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;


/**
 * Wrapper class to handle PAR request where the parameters of the request will be replaced
 * with the parameters obtained from the PAR request at the PAR endpoint by accessing the relevant
 * set of parameters for the submitted request_uri from the store.
 */
public class OAuthParRequestWrapper extends HttpServletRequestWrapper {

    private final Map<String, String> params;

    /**
     * Wraps the request with parameters obtained from the PAR endpoint.
     */
    public OAuthParRequestWrapper(HttpServletRequest request, ParAuthService parAuthService)
            throws OAuthProblemException {

        super(request);

        //get only uuid from request_uri
        String requestUri = request.getParameter(OAuthConstants.OAuth20Params.REQUEST_URI);
        String uuid = requestUri.replaceFirst(ParConstants.REQUEST_URI_PREFIX, "");

        try {
            if (parAuthService == null) {
                throw new ParAuthFailureException("ParAuthService is not initialized properly");
            }

            params = parAuthService.retrieveParams(uuid,
                    request.getParameter(OAuthConstants.OAuth20Params.CLIENT_ID));
            params.put(OAuthConstants.ALLOW_REQUEST_URI_AND_REQUEST_OBJECT_IN_REQUEST, "true");
        } catch (ParCoreException e) {
            throw new ParAuthFailureException(e.getMessage());
        }
    }

    /**
     * Get parameter.
     *
     * @return parameter from either this parameter map or from parameter map of super class
     */
    @Override
    public String getParameter(String name) {

        if (params.containsKey(name)) {
            return params.get(name);
        }

        return super.getParameter(name);
    }
}
