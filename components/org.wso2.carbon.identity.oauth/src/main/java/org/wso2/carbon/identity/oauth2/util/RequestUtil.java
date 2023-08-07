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
package org.wso2.carbon.identity.oauth2.util;

import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.oauth2.AbstractRequestBuilder;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

/**
 * This is a util class for building the request.
 */
public class RequestUtil {

    private RequestUtil() {

    }

    /**
     * This method builds the request according to the type which can handle it.
     *
     * @param request Incoming HttpServletRequest.
     * @return Built HttpServletRequest instance.
     * @throws IdentityException IdentityException.
     */
    public static HttpServletRequest buildRequest(HttpServletRequest request) throws IdentityException {

        List<AbstractRequestBuilder> abstractRequestBuilders =
                OAuth2ServiceComponentHolder.getInstance().getRequestBuilders();

        for (AbstractRequestBuilder requestBuilder : abstractRequestBuilders) {
            if (requestBuilder.canHandle(request)) {
                return requestBuilder.buildRequest(request);
            }
        }

        return request;
    }
}
