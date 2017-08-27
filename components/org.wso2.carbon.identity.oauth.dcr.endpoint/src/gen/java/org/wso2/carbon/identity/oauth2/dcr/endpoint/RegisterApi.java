package org.wso2.carbon.identity.oauth2.dcr.endpoint;

import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.*;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.RegisterApiService;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.factories.RegisterApiServiceFactory;

import io.swagger.annotations.ApiParam;

import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.ErrorDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.ApplicationDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.RegistrationRequestDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.UpdateRequestDTO;

import java.util.List;

import java.io.InputStream;
import org.apache.cxf.jaxrs.ext.multipart.Attachment;
import org.apache.cxf.jaxrs.ext.multipart.Multipart;

import javax.ws.rs.core.Response;
import javax.ws.rs.*;

@Path("/register")
@Consumes({ "application/json" })
@Produces({ "application/json" })
@io.swagger.annotations.Api(value = "/register", description = "the register API")
public class RegisterApi  {

   private final RegisterApiService delegate = RegisterApiServiceFactory.getRegisterApi();

    @DELETE
    @Path("/{client_id}")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Delete OAuth2 application\n", notes = "This API is used to delete OAuth2 application by client_id.\n", response = void.class)
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 204, message = "Successful deleted"),
        
        @io.swagger.annotations.ApiResponse(code = 404, message = "Not Found"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response deleteApplication(@ApiParam(value = "",required=true ) @PathParam("client_id") String clientId)
    {
    return delegate.deleteApplication(clientId);
    }
    @GET
    @Path("/{client_id}")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Get OAuth2 application information\n", notes = "This API is used to get OAuth2 application by client_id.\n", response = ApplicationDTO.class)
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 200, message = "Successful Retrieved"),
        
        @io.swagger.annotations.ApiResponse(code = 404, message = "Not Found"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response getApplication(@ApiParam(value = "",required=true ) @PathParam("client_id") String clientId)
    {
    return delegate.getApplication(clientId);
    }
    @POST
    
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Registers a oauth2 application\n", notes = "This API is used to create a OAuth2 application.\n", response = ApplicationDTO.class)
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 201, message = "Created"),
        
        @io.swagger.annotations.ApiResponse(code = 400, message = "Bad Request"),
        
        @io.swagger.annotations.ApiResponse(code = 409, message = "Conflict"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response registerApplication(@ApiParam(value = "Application information to register" ,required=true ) RegistrationRequestDTO registrationRequest)
    {
    return delegate.registerApplication(registrationRequest);
    }
    @PUT
    @Path("/{client_id}")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Registers a oauth2 application\n", notes = "This API is used to create a OAuth2 application.\n", response = ApplicationDTO.class)
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 200, message = "Successful updated"),
        
        @io.swagger.annotations.ApiResponse(code = 400, message = "Bad Request"),
        
        @io.swagger.annotations.ApiResponse(code = 409, message = "Conflict"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response updateApplication(@ApiParam(value = "Application information to update" ,required=true ) UpdateRequestDTO updateRequest,
    @ApiParam(value = "",required=true ) @PathParam("client_id") String clientId)
    {
    return delegate.updateApplication(updateRequest,clientId);
    }
}

