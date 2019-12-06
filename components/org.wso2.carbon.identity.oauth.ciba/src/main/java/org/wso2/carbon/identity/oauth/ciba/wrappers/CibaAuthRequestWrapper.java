/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth.ciba.wrappers;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthRequestWrapper;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

/**
 * Wrap ciba authentication request to remove unwanted params and added required params.
 */
public class CibaAuthRequestWrapper extends CommonAuthRequestWrapper {

    // Map to accumulate additional parameters.
    private Map<String, String> extraParameters;

    private static final Log log = LogFactory.getLog(CibaAuthRequestWrapper.class);

    public CibaAuthRequestWrapper(HttpServletRequest request) {

        super(request);
        extraParameters = new HashMap();
    }

    @Override
    public String getParameter(String name) {

        if (extraParameters.containsKey(name)) {
            return extraParameters.get(name);
        } else {
            if ((CibaConstants.REQUEST.equals(name))) {
                // Removing 'request' parameter which denotes the CIBA request.
                // This is to prevent conflict with 'request' param in OAuth2
                // which is usually used to denote request object.
                return null;
            }
            return super.getParameter(name);
        }
    }

    @Override
    public void setParameter(String name, String value) {

        extraParameters.put(name, value);
    }

    @Override
    public Map<String, String[]> getParameterMap() {

        Map<String, String[]> parameterMap = new HashMap<>(super.getParameterMap());
        extraParameters.forEach((key, value) -> parameterMap.put(key, new String[]{value}));
        parameterMap.remove(CibaConstants.REQUEST);
        return Collections.unmodifiableMap(parameterMap);
    }
}
