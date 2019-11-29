/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.ciba.api;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthResponseDTO;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.ciba.util.CibaAuthUtil;

/**
 * Provides authentication services.
 */
public class CibaAuthServiceImpl implements CibaAuthService {

    private static Log log = LogFactory.getLog(CibaAuthServiceImpl.class);

    @Override
    public CibaAuthResponseDTO generateAuthResponseDTO(CibaAuthRequestDTO cibaAuthRequestDTO) throws CibaCoreException {

        if (log.isDebugEnabled()) {
            log.debug("Creating Authentication Response DTO for the authentication request by the client: " +
                    cibaAuthRequestDTO.getIssuer());
        }
        return processRequest(cibaAuthRequestDTO);
    }

    /**
     * Accepts authentication request DTO, creates DO,persists and respond with responseDTO.
     *
     * @param cibaAuthRequestDTO CIBA Authentication Request Data Transfer Object.
     * @return CibaAuthResponseDTO
     * @throws CibaCoreException
     */
    private CibaAuthResponseDTO processRequest(CibaAuthRequestDTO cibaAuthRequestDTO) throws CibaCoreException {

        // Build DO that to be persisted.
        CibaAuthCodeDO cibaAuthCodeDO = CibaAuthUtil.generateCibaAuthCodeDO(cibaAuthRequestDTO);

        // Persist DO.
        CibaAuthUtil.persistCibaAuthCode(cibaAuthCodeDO);

        // Return built ResponseDTO.
        return CibaAuthUtil.buildAuthResponseDTO(cibaAuthRequestDTO, cibaAuthCodeDO);
    }
}
