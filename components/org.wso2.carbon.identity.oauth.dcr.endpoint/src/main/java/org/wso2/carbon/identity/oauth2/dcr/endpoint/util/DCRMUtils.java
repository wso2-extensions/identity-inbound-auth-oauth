/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.dcr.endpoint.util;

import org.apache.commons.logging.Log;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth.dcr.DCRMConstants;
import org.wso2.carbon.identity.oauth.dcr.bean.ApplicationRegistrationRequest;
import org.wso2.carbon.identity.oauth.dcr.bean.ApplicationUpdateRequest;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMException;
import org.wso2.carbon.identity.oauth.dcr.service.DCRMService;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.Exceptions.DCRMEndpointException;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.ErrorDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.RegistrationRequestDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.UpdateRequestDTO;

import javax.ws.rs.core.Response;

/**
 * This class holds Utils for DCRM endpoint component
 */
public class DCRMUtils {

    private static final String CONFLICT_STATUS = "CONFLICT_";
    private static final String BAD_REQUEST_STATUS = "BAD_REQUEST_";
    private static final String NOT_FOUND_STATUS = "NOT_FOUND_";

    public static DCRMService getOAuth2DCRMService() {
        return (DCRMService) PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getOSGiService(DCRMService.class, null);
    }

    public static ApplicationRegistrationRequest getApplicationRegistrationRequest(RegistrationRequestDTO registrationRequestDTO) {

        ApplicationRegistrationRequest appRegistrationRequest = new ApplicationRegistrationRequest();
        appRegistrationRequest.setClientName(registrationRequestDTO.getClientName());
        appRegistrationRequest.setRedirectUris(registrationRequestDTO.getRedirectUris());
        appRegistrationRequest.setGrantTypes(registrationRequestDTO.getGrantTypes());
        return appRegistrationRequest;

    }

    public static ApplicationUpdateRequest getApplicationUpdateRequest(UpdateRequestDTO updateRequestDTO) {

        ApplicationUpdateRequest applicationUpdateRequest = new ApplicationUpdateRequest();
        applicationUpdateRequest.setClientName(updateRequestDTO.getClientName());
        applicationUpdateRequest.setRedirectUris(updateRequestDTO.getRedirectUris());
        applicationUpdateRequest.setGrantTypes(updateRequestDTO.getGrantTypes());
        return applicationUpdateRequest;

    }

    public static void handleErrorResponse(Throwable throwable, Log log) throws DCRMEndpointException {
        String errorCode = ((DCRMException) throwable).getErrorCode();
        Response.Status status = Response.Status.INTERNAL_SERVER_ERROR;
        if (errorCode != null) {
            if (errorCode.startsWith(CONFLICT_STATUS)) {
                status = Response.Status.CONFLICT;
            } else if (errorCode.startsWith(BAD_REQUEST_STATUS)) {
                status = Response.Status.BAD_REQUEST;
            } else if (errorCode.startsWith(NOT_FOUND_STATUS)){
                status = Response.Status.NOT_FOUND;
            }
        }
        handleErrorResponse(status, throwable, false, log);
    }

    /**
     * Logs the error, builds a DCRMEndpointException with specified details and throws it
     *
     * @param status    response status
     * @param throwable throwable
     * @throws DCRMEndpointException
     */
    public static void handleErrorResponse(Response.Status status, Throwable throwable,
                                           boolean isServerException, Log log)
            throws DCRMEndpointException {

        String errorCode;
        if (throwable instanceof DCRMException) {
            errorCode = ((DCRMException) throwable).getErrorCode();
        } else {
            errorCode = DCRMConstants.ErrorMessages.ERROR_CODE_UNEXPECTED.getCode();
        }

        if (isServerException) {
            if (throwable == null) {
                log.error(status.getReasonPhrase());
            } else {
                log.error(status.getReasonPhrase(), throwable);
            }
        }
        throw buildDCRMEndpointException(status, errorCode, throwable == null ? "" : throwable.getMessage(),
                isServerException);
    }

    private static DCRMEndpointException buildDCRMEndpointException(Response.Status status,
                                                                    String code, String description,
                                                                    boolean isServerException) {
        ErrorDTO errorDTO = new ErrorDTO();
        errorDTO.setCode(code);
        errorDTO.setMessage(status.getReasonPhrase());
        errorDTO.setDescription(description);

        if (isServerException) {
            return new DCRMEndpointException(status);
        } else {
            return new DCRMEndpointException(status, errorDTO);
        }
    }

}
