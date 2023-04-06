/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.oauth2;

/**
 * This service handles token revocations validations due to internal events.
 * For example token revocations due to application deletion, user deletion, client secret regeneration, user profile
 * claim updates and etc...
 */
public interface InternalTokenRevocationService {

    /**
     * Add token to the revocated token list.
     *
     * @param token     token to be added to revocated list.
     * @return          true if token added successfully.
     *                  false if token addition get failed.
     */
    boolean addTokenToRevocationList(String token);

    /**
     * Check whether a specific token is revoked or not
     * @param token     token needs to be checked.
     * @return          true if the token is revocated.
     *                  false if the token has not been revoked
     */
    boolean isTokenRevoked(String token);
}
