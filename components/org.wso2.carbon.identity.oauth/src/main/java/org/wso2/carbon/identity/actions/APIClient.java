/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.actions;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.wso2.carbon.identity.actions.model.ActionExecutionRequest;
import org.wso2.carbon.identity.actions.model.ActionExecutionResponse;

/**
 * APIClient.
 */
public class APIClient {

    private static final Log log = LogFactory.getLog(APIClient.class);
    private final CloseableHttpClient httpClient;
    private final int connectionTimeout = 2000;
    private final int connectionRequestTimeout = 2000;
    private final int readTimeout = 5000;

    public APIClient() {
        // Initialize the http client. Set connection time out to 2s and read time out to 5s.
        RequestConfig config = RequestConfig.custom()
                .setConnectTimeout(connectionTimeout)
                .setConnectionRequestTimeout(connectionRequestTimeout)
                .setSocketTimeout(readTimeout)
                .setRedirectsEnabled(false)
                .setRelativeRedirectsAllowed(false)
                .build();
        httpClient = HttpClientBuilder.create().setDefaultRequestConfig(config).build();
    }

    public ActionExecutionResponse callAPI(String url, ActionExecutionRequest request) {

        try {
            // Create a HttpPost request
            HttpPost httpPost = new HttpPost(url);

            // Convert the ActionInvocationRequest object to JSON string
            ObjectMapper requestObjectmapper = new ObjectMapper();
            requestObjectmapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
            requestObjectmapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);

            String jsonRequest = requestObjectmapper.writeValueAsString(request);

            log.info("=== Action Request: \n" + jsonRequest);

            // Set the JSON string as the request body
            StringEntity entity = new StringEntity(jsonRequest);
            httpPost.setEntity(entity);
            httpPost.setHeader("Accept", "application/json");
            httpPost.setHeader("Content-type", "application/json");

            // Execute the request and get the response
            CloseableHttpResponse response = httpClient.execute(httpPost);

            // Extract the JSON string from the response
            HttpEntity responseEntity = response.getEntity();
            String jsonResponse = EntityUtils.toString(responseEntity);

            ObjectMapper objectMapper = new ObjectMapper();
            ActionExecutionResponse actionExecutionResponse =
                    objectMapper.readValue(jsonResponse, ActionExecutionResponse.class);

            return actionExecutionResponse;
        } catch (Exception e) {
            log.error("Failed to invoke the http endpoint: " + url, e);

            return null;
        }
    }

}
