package org.wso2.carbon.identity.oauth.endpoint.par;

import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.endpoint.OAuthRequestWrapper;
import org.wso2.carbon.identity.oauth.endpoint.exception.CibaAuthFailureException;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.List;
import java.util.Map;


@Path("/par")
public class OAuth2ParEndpoint {

//    @POST
//    @Produces("text/plain")
//    public String getClichedMessage(String msg) {
//        return "Stored Message";
//    }

    @POST
    @Path("/")
//    @Consumes("application/json")
//    @Produces("application/json")
    @Produces("text/plain")
    public Response par(@Context HttpServletRequest request, @Context HttpServletResponse response, MultivaluedMap paramMap) {

        return null;
    }

}
