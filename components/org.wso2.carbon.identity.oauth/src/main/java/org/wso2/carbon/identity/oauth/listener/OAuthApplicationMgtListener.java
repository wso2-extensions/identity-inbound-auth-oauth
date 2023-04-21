/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.listener;

import java.util.Properties;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;

/**
 * Listener interface for OAuth application management CRUD operations.
 */
public interface OAuthApplicationMgtListener {

    /**
     * Returns whether the listener is enabled.
     *
     * @return true if listener is enabled.
     */
    boolean isEnabled();

    /**
     * Returns the execution order of the listener.
     *
     * @return execution order.
     */
    int getExecutionOrder();

    /**
     * Pre-listener for the update consumer application.
     *
     * @param consumerAppDTO consumer app DTO.
     * @throws IdentityOAuthAdminException in case of failure.
     */
    void doPreUpdateConsumerApplication(OAuthConsumerAppDTO consumerAppDTO) throws IdentityOAuthAdminException;

    /**
     * Pre-listener for the update consumer app state.
     *
     * @param consumerKey consumer key.
     * @param newState    new state.
     * @throws IdentityOAuthAdminException in case of failure.
     */
    void doPreUpdateConsumerApplicationState(String consumerKey, String newState) throws IdentityOAuthAdminException;

    /**
     * Pre-listener for the remove OAuth application data.
     *
     * @param consumerKey consumer key.
     * @throws IdentityOAuthAdminException in case of failure.
     */
    void doPreRemoveOAuthApplicationData(String consumerKey) throws IdentityOAuthAdminException;

    /**
     *
     * @throws IdentityOAuthAdminException
     */
    void doPostRevokeOAuthSecret(String consumerKey, Properties properties) throws IdentityOAuthAdminException;

    /**
     * 
     * @throws IdentityOAuthAdminException
     */
    void doPostRegenerateOAuthSecret(String consumerKey, Properties properties) throws IdentityOAuthAdminException;
}
