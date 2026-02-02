/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.config.services;

import org.wso2.carbon.identity.oauth2.config.exceptions.OAuth2OIDCConfigMgtException;
import org.wso2.carbon.identity.oauth2.config.models.IssuerDetails;
import org.wso2.carbon.identity.oauth2.config.models.OAuth2OIDCConfig;

import java.util.List;

/**
 * Service interface for OAuth2 / OIDC configuration management.
 */
public interface OAuth2OIDCConfigMgtService {

    OAuth2OIDCConfig getOAuth2OIDCConfigs(String tenantDomain) throws OAuth2OIDCConfigMgtException;

    OAuth2OIDCConfig updateOAuth2OIDCConfigs(String tenantDomain, OAuth2OIDCConfig oAuth2OIDCConfig)
            throws OAuth2OIDCConfigMgtException;

    List<String> getAllowedIssuers() throws OAuth2OIDCConfigMgtException;

    List<IssuerDetails> getAllowedIssuerDetails() throws OAuth2OIDCConfigMgtException;
}
