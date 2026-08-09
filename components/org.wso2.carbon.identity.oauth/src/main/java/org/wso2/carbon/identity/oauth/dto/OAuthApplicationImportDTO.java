/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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
package org.wso2.carbon.identity.oauth.dto;

import java.util.List;

/**
 * Carries an OAuth application and its additional client secrets to be restored during import. The latest secret
 * and its expiry travel on the application; the additional secrets travel as a separate list.
 */
public class OAuthApplicationImportDTO {

    private OAuthConsumerAppDTO application;
    private List<OAuthClientSecretImportDTO> additionalSecrets;

    public OAuthConsumerAppDTO getApplication() {

        return application;
    }

    public void setApplication(OAuthConsumerAppDTO application) {

        this.application = application;
    }

    public List<OAuthClientSecretImportDTO> getAdditionalSecrets() {

        return additionalSecrets;
    }

    public void setAdditionalSecrets(List<OAuthClientSecretImportDTO> additionalSecrets) {

        this.additionalSecrets = additionalSecrets;
    }
}
