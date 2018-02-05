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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.dao;

import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;

/*
NOTE
This is the very first step of moving to simplified architecture for token persistence. New set of DAO classes  for
each purpose  and factory class to get instance of each DAO classes were introduced  during  this step. Further methods
 on org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO were distributed among new set of classes, each of these method
 need to be reviewed  and refactored  during next step.
 */
public class AccessContextTokenDO {

    private String accessToken;
    private String consumerKey;
    private AccessTokenDO newAccessTokenDO;
    private AccessTokenDO existingAccessTokenDO;
    private String userStoreDomain;

    public AccessContextTokenDO(String accessToken, String consumerKey, AccessTokenDO newAccessTokenDO, AccessTokenDO
            existingAccessTokenDO, String userStoreDomain) {
        this.accessToken = accessToken;
        this.consumerKey = consumerKey;
        this.newAccessTokenDO = newAccessTokenDO;
        this.existingAccessTokenDO = existingAccessTokenDO;
        this.userStoreDomain = userStoreDomain;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getConsumerKey() {
        return consumerKey;
    }

    public AccessTokenDO getNewAccessTokenDO() {
        return newAccessTokenDO;
    }

    public String getUserStoreDomain() {
        return userStoreDomain;
    }

    public AccessTokenDO getExistingAccessTokenDO() {
        return existingAccessTokenDO;
    }
}
