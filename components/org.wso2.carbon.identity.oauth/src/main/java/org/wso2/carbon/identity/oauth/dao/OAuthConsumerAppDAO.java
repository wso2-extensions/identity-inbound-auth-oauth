/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.identity.oauth.dao;

import org.wso2.carbon.identity.oauth.exception.OAuthConsumerAppException;

/**
 * Performs the operations related to OAuth consumer application.
 */
public interface OAuthConsumerAppDAO {

    /**
     * Add OAuth Consumer application.
     *
     * @param consumerAppDO {@link OAuthAppDO} to add
     * @throws OAuthConsumerAppException if error occurs while adding the {@link OAuthAppDO}
     */
    void addOAuthConsumerApplication(OAuthAppDO consumerAppDO) throws OAuthConsumerAppException;

    /**
     * Retrieve {@link OAuthAppDO} for consumer key.
     *
     * @param consumerKey Consumer key of {@link OAuthAppDO} to be retrieved
     * @return {@link OAuthAppDO} for the given consumer key
     * @throws OAuthConsumerAppException if error occurs while retrieving the {@link OAuthAppDO}
     */
    OAuthAppDO getAppInformationByConsumerKey(String consumerKey) throws OAuthConsumerAppException;

    /**
     * Retrieve {@link OAuthAppDO} using the application name.
     *
     * @param appName name of the {@link OAuthAppDO} to be retrieved
     * @return {@link OAuthAppDO} for the given application name
     * @throws OAuthConsumerAppException if error occurs while retrieving the {@link OAuthAppDO}
     */
    OAuthAppDO getAppInformationByAppName(String appName) throws OAuthConsumerAppException;

    /**
     * Retrieve an array of {@link OAuthAppDO} belongs to an user.
     *
     * @param username user to retrieve the OAuth apps belongs to
     * @param tenantId ID of the tenant domain to be searched.
     * @return an array of {@link OAuthAppDO} own by the given user
     * @throws OAuthConsumerAppException if error occurs while retrieving the array of {@link OAuthAppDO} belong to
     *                                   the user
     */
    OAuthAppDO[] getOAuthConsumerAppsOfUser(String username,
                                            int tenantId) throws OAuthConsumerAppException;

    /**
     * Retrieve consumer secret of the OAuth application using the consumer key.
     *
     * @param consumerKey consumer key of the OAuth application to retrieve consumer secret
     * @return the consumer secret for the consumer key
     * @throws OAuthConsumerAppException if error occurs while retrieving the consumer secret for the consumer key
     */
    String getOAuthConsumerSecret(String consumerKey) throws OAuthConsumerAppException;

    /**
     * Retrieve the username corresponding to a given consumer key.
     *
     * @param consumerKey consumer key of the OAuth application to retrieve the user
     * @return the username of the user owns the consumer application with the giver consumer key
     * @throws OAuthConsumerAppException f error occurs while retrieving the username
     */
    String getConsumerApplicationOwnerName(String consumerKey) throws OAuthConsumerAppException;

    /**
     * Update the OAuth consumer application with the given {@link OAuthAppDO}.
     *
     * @param oauthAppDO latest {@link OAuthAppDO} to be used to update the OAuth application
     * @throws OAuthConsumerAppException if error occurs while updating the OAuth consumer application
     */
    void updateOAuthConsumerApplication(OAuthAppDO oauthAppDO) throws OAuthConsumerAppException;

    /**
     * Update the application name of the OAuth consumer application.
     *
     * @param consumerKey consumer key of the application which the application name need to be updated
     * @param appName     the latest application name of the OAuth application to be updated
     * @throws OAuthConsumerAppException if error occurs while updating the application name of the OAuth application
     */
    void updateOAuthConsumerAppName(String consumerKey,
                                    String appName) throws OAuthConsumerAppException;

    /**
     * Update the consumer secret of the OAuth consumer application.
     *
     * @param consumerKey consumer key of the application which the consumer secret need to be updated.
     * @param consumerSecret the new consumer secret of the OAuth application to be updated
     * @throws OAuthConsumerAppException if error occurs while updating the consumer key of the OAuth application
     */
    void updateOAuthConsumerSecret(String consumerKey,
                                   String consumerSecret) throws OAuthConsumerAppException;

    /**
     * Update the application state of the OAuth consumer application.
     *
     * @param consumerKey consumer key of the application which the state need to be updated.
     * @param state the state of the OAuth application to be updated
     * @throws OAuthConsumerAppException if error occurs while updating the state of the OAuth application
     */
    void updateOAuthConsumerAppState(String consumerKey,
                                     String state) throws OAuthConsumerAppException;

    /**
     * Remove OAuth consumer application.
     *
     * @param consumerKey consumer key to identify the OAuth application to be removed
     * @throws OAuthConsumerAppException if error occurs while removing the OAuth application
     */
    void removeOAuthConsumerApplication(String consumerKey) throws OAuthConsumerAppException;

    /**
     * Remove OAuth consumer app related properties.
     *
     * @param consumerKey  consumer key to identify the OAuth consumer app related properties
     * @param tenantDomain tenant domain of the OAuth application
     * @throws OAuthConsumerAppException if error occurs while removing the OAuth consumer app related properties
     */
    void removeOIDCProperties(String consumerKey,
                              String tenantDomain) throws OAuthConsumerAppException;

}
