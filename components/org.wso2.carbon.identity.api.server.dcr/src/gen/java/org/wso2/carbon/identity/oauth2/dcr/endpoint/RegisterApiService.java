package org.wso2.carbon.identity.oauth2.dcr.endpoint;

import org.wso2.carbon.identity.oauth2.dcr.endpoint.*;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.*;

import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.ErrorDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.ApplicationDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.RegistrationRequestDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.UpdateRequestDTO;

import java.util.List;

import java.io.InputStream;
import org.apache.cxf.jaxrs.ext.multipart.Attachment;

import javax.ws.rs.core.Response;

public abstract class RegisterApiService {
    public abstract Response deleteApplication(String clientId);
    public abstract Response getApplication(String clientId);
    public abstract Response registerApplication(RegistrationRequestDTO registrationRequest);
    public abstract Response updateApplication(UpdateRequestDTO updateRequest,String clientId);
    public abstract Response getApplicationByName(String clientName);
}

