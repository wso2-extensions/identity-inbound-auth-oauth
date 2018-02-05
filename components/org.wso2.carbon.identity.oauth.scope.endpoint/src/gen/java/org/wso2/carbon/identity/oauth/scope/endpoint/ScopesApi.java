package org.wso2.carbon.identity.oauth.scope.endpoint;

import org.wso2.carbon.identity.oauth.scope.endpoint.dto.*;
import org.wso2.carbon.identity.oauth.scope.endpoint.ScopesApiService;
import org.wso2.carbon.identity.oauth.scope.endpoint.factories.ScopesApiServiceFactory;

import io.swagger.annotations.ApiParam;

import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ErrorDTO;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ScopeToUpdateDTO;

import java.util.List;

import java.io.InputStream;
import org.apache.cxf.jaxrs.ext.multipart.Attachment;
import org.apache.cxf.jaxrs.ext.multipart.Multipart;

import javax.ws.rs.core.Response;
import javax.ws.rs.*;

@Path("/scopes")
@Consumes({ "application/json" })
@Produces({ "application/json" })
@io.swagger.annotations.Api(value = "/scopes", description = "the scopes API")
public class ScopesApi  {

   private final ScopesApiService delegate = ScopesApiServiceFactory.getScopesApi();

    @DELETE
    @Path("/name/{name}")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Deletes a Scope\n", notes = "This API is used to delete a scope by a given scope name.\n", response = String.class)
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 204, message = "Successfully deleted"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response deleteScope(@ApiParam(value = "Name of the scope that is to be deleted",required=true ) @PathParam("name") String name)
    {
    return delegate.deleteScope(name);
    }
    @GET
    @Path("/name/{name}")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Returns a Scope by Scope Name\n", notes = "This API is used to retrieve details of a scope by a given scope name.\n", response = ScopeDTO.class)
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 200, message = "Successfully Retrieved"),
        
        @io.swagger.annotations.ApiResponse(code = 404, message = "Not Found"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response getScope(@ApiParam(value = "Name of the scope that is to be retrieved",required=true ) @PathParam("name") String name)
    {
    return delegate.getScope(name);
    }
    @GET
    
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Returns all available Scopes\n", notes = "This API is used to get all the available scopes.\n", response = ScopeDTO.class, responseContainer = "List")
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 200, message = "Successfully Retrieved"),
        
        @io.swagger.annotations.ApiResponse(code = 404, message = "Not Found"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response getScopes(@ApiParam(value = "The start index of the list of scopes to be retrieved") @QueryParam("startIndex") Integer startIndex,
    @ApiParam(value = "Number of scopes to retrieve from the point of the start index") @QueryParam("count") Integer count)
    {
    return delegate.getScopes(startIndex,count);
    }
    @HEAD
    @Path("/name/{name}")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Check Scope Existance using Scope Name\n", notes = "This API is used to check a scope's existance using a given scope name.\n", response = String.class)
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 200, message = "Scope Exists"),
        
        @io.swagger.annotations.ApiResponse(code = 404, message = "Not Found"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response isScopeExists(@ApiParam(value = "Name of the scope that is to be checked",required=true ) @PathParam("name") String name)
    {
    return delegate.isScopeExists(name);
    }
    @POST
    
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Registers a Scope\n", notes = "This API is used to create a scope.\n", response = ScopeDTO.class)
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 201, message = "Successfully Created"),
        
        @io.swagger.annotations.ApiResponse(code = 400, message = "Bad Request"),
        
        @io.swagger.annotations.ApiResponse(code = 409, message = "Conflict"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response registerScope(@ApiParam(value = "Define a scope with bindings to register it" ,required=true ) ScopeDTO scope)
    {
    return delegate.registerScope(scope);
    }
    @PUT
    @Path("/name/{name}")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Updates a Scope\n", notes = "This API is used to update a scope by a given scope name.\n", response = ScopeDTO.class)
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 200, message = "Successfully updated"),
        
        @io.swagger.annotations.ApiResponse(code = 409, message = "Conflict"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response updateScope(@ApiParam(value = "updated scope" ,required=true ) ScopeToUpdateDTO scope,
    @ApiParam(value = "Name of the scope that is to be updated",required=true ) @PathParam("name") String name)
    {
    return delegate.updateScope(scope,name);
    }
}

