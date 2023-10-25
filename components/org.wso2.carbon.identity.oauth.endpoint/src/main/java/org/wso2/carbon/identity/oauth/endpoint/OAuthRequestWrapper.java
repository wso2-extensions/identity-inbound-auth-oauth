/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.endpoint;

import org.apache.commons.collections.CollectionUtils;

import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.ws.rs.core.MultivaluedMap;

/**
 * Wrapper class to handle OAuth request.
 */
public class OAuthRequestWrapper extends HttpServletRequestWrapper {

    private Map<String, List<String>> form;
    private Enumeration<String> parameterNames;

    private boolean isInternalRequest = false;

    @Deprecated
    public OAuthRequestWrapper(HttpServletRequest request, MultivaluedMap<String, String> form) {

        this(request, (Map<String, List<String>>) form);
    }

    public OAuthRequestWrapper(HttpServletRequest request, Map<String, List<String>> form) {

        super(request);
        this.form = form;

        Set<String> parameterNameSet = new HashSet<>();
        // Add post parameters
        parameterNameSet.addAll(form.keySet());
        // Add servlet request parameters
        Enumeration<String> requestParameterNames = request.getParameterNames();
        while (requestParameterNames.hasMoreElements()) {
            parameterNameSet.add(requestParameterNames.nextElement());
        }

        this.parameterNames = Collections.enumeration(parameterNameSet);
    }

    @Override
    public String getParameter(String name) {

        String value = super.getParameter(name);
        if (value == null || isInternalRequest) {
            if (CollectionUtils.isNotEmpty(form.get(name))) {
                value = form.get(name).get(0);
            }
        }
        return value;
    }

    @Override
    public Enumeration<String> getParameterNames() {

        return parameterNames;
    }

    /**
     * Set whether the request is internal or not.
     * If the request is internal, the request parameters
     * in the wrapper will get priority over the servlet request.
     *
     * @param internalRequest Whether the request is internal or not.
     */
    public void setInternalRequest(boolean internalRequest) {

        isInternalRequest = internalRequest;
    }

    @Override
    public Map<String, String[]> getParameterMap() {

        Map<String, String[]> parameterMap = new HashMap<>(super.getParameterMap());

        // Add form data to parameterMap.
        for (Map.Entry<String, List<String>> entry : form.entrySet()) {
            parameterMap.put(entry.getKey(), entry.getValue().toArray(new String[0]));
        }

        return parameterMap;
    }
}
