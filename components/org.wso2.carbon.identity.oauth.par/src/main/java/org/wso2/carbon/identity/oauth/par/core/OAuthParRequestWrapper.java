/*
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
package org.wso2.carbon.identity.oauth.par.core;

import org.wso2.carbon.identity.oauth.common.OAuthConstants;

import java.util.Collections;
import java.util.HashMap;
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
     *
     * @param request HttpServletRequest.
     */
    public OAuthParRequestWrapper(HttpServletRequest request, Map<String, String> params) {

        super(request);
        this.params = params;
    }

    /**
     * Get parameter.
     *
     * @param name Name of the parameter.
     * @return Parameter from either this parameter map or from parameter map of super class.
     */
    @Override
    public String getParameter(String name) {

        // Remove param request_uri to avoid conflicting with OIDC requests passed by reference.
        if (OAuthConstants.OAuth20Params.REQUEST_URI.equals(name)) {
            return null;
        }
        if (params.containsKey(name)) {
            return params.get(name);
        }
        return super.getParameter(name);
    }

    @Override
    public Map<String, String[]> getParameterMap() {

        Map<String, String[]> parameterMap = new HashMap<>(super.getParameterMap());
        params.forEach((key, value) -> parameterMap.put(key, new String[]{value}));
        parameterMap.remove(OAuthConstants.OAuth20Params.REQUEST_URI);
        return Collections.unmodifiableMap(parameterMap);
    }
}
