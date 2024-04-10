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

package org.wso2.carbon.identity.oauth.dcr;

import org.wso2.carbon.identity.oauth.dcr.exception.DCRMClientException;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMServerException;
import org.wso2.carbon.identity.oauth.dcr.model.DCRConfiguration;
import org.wso2.carbon.identity.oauth.dcr.util.DCRConfigUtils;

/**
 * Service layer implementation for managing the DCR configurations of a tenant.
 */
public class DCRConfigurationMgtServiceImpl implements DCRConfigurationMgtService {

    /**
     * {@inheritDoc}
     */
    @Override
    public DCRConfiguration getDCRConfiguration() throws DCRMServerException {

        return DCRConfigUtils.getDCRConfiguration();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setDCRConfiguration(DCRConfiguration dcrConfiguration)
            throws DCRMServerException, DCRMClientException {

        DCRConfigUtils.setDCRConfiguration(dcrConfiguration);
    }
}
