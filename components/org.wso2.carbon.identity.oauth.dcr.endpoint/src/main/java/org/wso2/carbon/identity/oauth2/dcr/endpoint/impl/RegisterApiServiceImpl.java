/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.oauth2.dcr.endpoint.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.dcr.bean.Application;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMClientException;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMServerException;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.RegisterApiService;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.RegistrationRequestDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.UpdateRequestDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.util.DCRMUtils;

import javax.ws.rs.core.Response;

public class RegisterApiServiceImpl extends RegisterApiService {

    private static final Log LOG = LogFactory.getLog(RegisterApiServiceImpl.class);

    @Override
    public Response deleteApplication(String clientId) {
        try {
            DCRMUtils.getOAuth2DCRMService().deleteApplication(clientId);
        } catch (DCRMClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client error while deleting  application with client key:" + clientId, e);
            }
            DCRMUtils.handleErrorResponse(e, LOG);
        } catch (DCRMServerException e) {
            DCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, e, true, LOG);

        } catch (Throwable throwable) {
            DCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, throwable, true, LOG);
        }
        return Response.status(Response.Status.NO_CONTENT).build();
    }

    @Override
    public Response getApplication(String clientId) {
        Application application = null;
        try {
            application = DCRMUtils.getOAuth2DCRMService().getApplication(clientId);
        } catch (DCRMClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client error while retrieving  application with client key:" + clientId, e);
            }
            DCRMUtils.handleErrorResponse(e, LOG);
        } catch (DCRMServerException e) {
            DCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, e, true, LOG);

        } catch (Throwable throwable) {
            DCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, throwable, true, LOG);
        }
        return Response.status(Response.Status.OK).entity(application).build();
    }

    @Override
    public Response registerApplication(RegistrationRequestDTO registrationRequest) {
        Application application = null;
        try {
            application = DCRMUtils.getOAuth2DCRMService().registerApplication(DCRMUtils.getApplicationRegistrationRequest(registrationRequest));
        } catch (DCRMClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client error while registering application \n" + registrationRequest.toString(), e);
            }
            DCRMUtils.handleErrorResponse(e, LOG);
        } catch (DCRMServerException e) {
            DCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, e, true, LOG);

        } catch (Throwable throwable) {
            DCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, throwable, true, LOG);
        }
        return Response.status(Response.Status.CREATED).entity(application).build();
    }

    @Override
    public Response updateApplication(UpdateRequestDTO updateRequest, String clientId) {
        Application application = null;
        try {
            application = DCRMUtils.getOAuth2DCRMService().updateApplication(DCRMUtils.getApplicationUpdateRequest(updateRequest), clientId);
        } catch (DCRMClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client error while updating application \n" + updateRequest.toString(), e);
            }
            DCRMUtils.handleErrorResponse(e, LOG);
        } catch (DCRMServerException e) {
            DCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, e, true, LOG);

        } catch (Throwable throwable) {
            DCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, throwable, true, LOG);
        }
        return Response.status(Response.Status.OK).entity(application).build();
    }

    @Override
    public Response getApplicationByName(String name) {

        Application application = null;
        try {
            application = DCRMUtils.getOAuth2DCRMService().getApplicationByName(name);
        } catch (DCRMClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client error while retrieving application by name : " + name, e);
            }
            DCRMUtils.handleErrorResponse(e, LOG);
        } catch (Exception e) {
            DCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, e, true, LOG);
        }
        return Response.status(Response.Status.OK).entity(application).build();
    }
}
