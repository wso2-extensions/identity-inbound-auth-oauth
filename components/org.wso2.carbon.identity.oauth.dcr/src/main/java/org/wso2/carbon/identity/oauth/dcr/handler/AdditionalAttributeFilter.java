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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.dcr.handler;

import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.oauth.dcr.bean.ApplicationRegistrationRequest;
import org.wso2.carbon.identity.oauth.dcr.bean.ApplicationUpdateRequest;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMClientException;

import java.util.List;
import java.util.Map;

/**
 * Interface class for filtering, validating and returning additional attributes in DCR requests
 */
public interface AdditionalAttributeFilter {

    /**
     * Filter and validate additional attributes in the DCR registration request. Other information of the DCR
     * registration request is also passed to the method to make decisions based on them. Additional attributes passed
     * as SSA claims also can be accessed here. The attributes returned from this method will be stored as service
     * provider metadata as String values. Of the returned attributes, the keys returned from the getAttributeKeys
     * method will be sent back in the DCR register response.
     * @param registrationRequest DCR registration request.
     * @param ssaClaims SSA claims.
     * @return Processed additional attributes to be stored and returned in the DCR register response.
     * @throws DCRMClientException In case of validation failure or any other blocking error.
     */
    Map<String, Object> filterDCRRegisterAttributes(ApplicationRegistrationRequest registrationRequest,
                                                    Map<String, Object> ssaClaims) throws DCRMClientException;

    /**
     * Filter and validate additional attributes in the DCR update request. Other information of the DCR update
     * request is also passed to the method to make decisions based on them. Additional attributes passed as SSA
     * claims also can be accessed here. The attributes returned from this method will be stored as service provider
     * metadata as String values. If any of the keys already exists as metadata, they will be updated. Of the returned
     * attributes, the keys returned from the getAttributeKeys method will be sent back in the DCR update response.
     * @param updateRequest DCR update request.
     * @param ssaClaims SSA claims.
     * @param spProp Existing service provider properties.
     * @return Processed additional attributes to be stored and returned in the DCR update response.
     * @throws DCRMClientException In case of validation failure or any other blocking error.
     */
    Map<String, Object> filterDCRUpdateAttributes(ApplicationUpdateRequest updateRequest, Map<String, Object> ssaClaims,
                                                  ServiceProviderProperty[] spProp) throws DCRMClientException;

    /**
     * Process the stored DCR additional attributes in the DCR GET request. Of the stored additional attributes in the
     * DCR register and update requests, the keys returned from the getAttributeKeys method will be sent into this
     * method. Since the attributes are stored as String values, they can be processed and converted to the required
     * type here before sending back in the DCR GET response.
     * @param storedAttributes Stored additional attributes for the application being retrieved.
     * @return Processed additional attributes to be sent in the DCR GET response.
     * @throws DCRMClientException In case of validation failure or any other blocking error.
     */
    Map<String, Object> processDCRGetAttributes(Map<String, String> storedAttributes) throws DCRMClientException;

    /**
     * Get the keys of additional attributes to be returned in the DCR register, update and get responses.
     * @return List of attribute keys.
     */
    List<String> getResponseAttributeKeys();

}
