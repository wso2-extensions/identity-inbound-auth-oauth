/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.responsemode.provider;

/**
 * Interface class for all response mode provider classes
 */
public interface ResponseModeProvider {

    /**
     * POST_RESPONSE - for 200 OK Responses like in form post response mode
     * REDIRECTION - for redirection url based response modes
     */
    enum AuthResponseType {

        POST_RESPONSE,
        REDIRECTION
    }

    /**
     * Get the response mode of the ResponseModeProvider instance
     * @return response_mode
     */
    String getResponseMode();

    /**
     * Check whether the authorization response can be handled using the relevant ResponseModeProvider
     * @param authorizationResponseDTO AuthorizationResponseDTO instance
     * @return true if relevant ResponseModeProvider can handle the given response_mode
     */
    boolean canHandle(AuthorizationResponseDTO authorizationResponseDTO);

    /**
     * Use this method only when AuthResponseType is set to REDIRECTION
     * This method build and return authorization response redirect url with necessary params appended to it
     * @param authorizationResponseDTO AuthorizationResponseDTO instance
     * @return authorization response redirect url
     */
    String getAuthResponseRedirectUrl(AuthorizationResponseDTO authorizationResponseDTO);

    /**
     * Use this method only when AuthResponseType is set to POST_RESPONSE
     * This method build and return authorization response as html page
     * @param authorizationResponseDTO AuthorizationResponseDTO instance
     * @return html content which is suitable to build a response as Response.ok(html_content).build()
     */
    String getAuthResponseBuilderEntity(AuthorizationResponseDTO authorizationResponseDTO);

    /**
     * Get the relevant AuthResponseType related to the implemented ResponseModeProvider
     * @return AuthResponseType : POST_RESPONSE or REDIRECTION
     */
    AuthResponseType getAuthResponseType();


}
