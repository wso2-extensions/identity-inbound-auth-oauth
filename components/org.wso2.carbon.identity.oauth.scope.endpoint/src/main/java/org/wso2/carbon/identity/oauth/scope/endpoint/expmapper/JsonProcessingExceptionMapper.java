
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.scope.endpoint.expmapper;

import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ErrorDTO;
import org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

/**
 * Handles exceptions when an incorrect json requests body is received.
 * Sends a default error response.
 */
public class JsonProcessingExceptionMapper implements ExceptionMapper<UnrecognizedPropertyException> {

    private static final Log log = LogFactory.getLog(JsonProcessingExceptionMapper.class);

    @Override
    public Response toResponse(UnrecognizedPropertyException e) {

        if (log.isDebugEnabled()) {
            log.debug("Provided JSON request content is not in the valid format:", e);
        }

        Oauth2ScopeConstants.ErrorMessages error = Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_BAD_REQUEST;

        ErrorDTO errorDTO = new ErrorDTO();
        errorDTO.setCode(error.getCode());
        errorDTO.setMessage(error.getMessage());
        errorDTO.setDescription(String.format("Unrecognized field : %s", e.getPropertyName()));

        return Response.status(Response.Status.BAD_REQUEST)
                .entity(errorDTO)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON).build();
    }
}
