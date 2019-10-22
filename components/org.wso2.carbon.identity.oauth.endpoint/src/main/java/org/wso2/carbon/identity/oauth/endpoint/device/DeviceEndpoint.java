package org.wso2.carbon.identity.oauth.endpoint.device;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.identity.oauth2.device.CodeGenerator.GenerateKeys;
import org.wso2.identity.oauth2.device.constants.Constants;
import org.wso2.identity.oauth2.device.dao.DeviceFlowPersistenceFactory;
import org.wso2.identity.oauth2.device.errorcodes.ErrorCodes;
import org.wso2.identity.oauth2.device.model.DeviceFlowDO;

import java.io.IOException;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

@Path("/device_authorize")
public class DeviceEndpoint {

    private static final Log log = LogFactory.getLog(DeviceEndpoint.class);
//    private

    @POST
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("application/json")
    public Response authorize(@Context HttpServletRequest request, @Context HttpServletResponse response)
            throws IOException, IdentityOAuth2Exception, InvalidOAuthClientException, OAuthSystemException {

        String userCode = new GenerateKeys().getKey(6);
        DeviceFlowDO deviceFlowDO = new DeviceFlowDO();
        String deviceCode = UUID.randomUUID().toString();
        String clientId = request.getParameter("client_id");
        String scope = request.getParameter("scope");
        String[] scopeSet = scope.split(" ");
        deviceFlowDO.setScope(scopeSet);
        String redirectionUri = IdentityUtil.getServerURL("/authenticationendpoint/device.do",
                false, false);
        String redirectionUriComplete = redirectionUri + "?user_code=" + userCode;
        Long expiresIn = 3600000L;
        Integer interval = 5000;
        OAuthResponse errorResponse;

        if (clientId != null) {
            if (validateClientId(clientId)) {

                DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().insertDeviceFlow(deviceCode, userCode,
                        clientId, scope, expiresIn);

                OAuthResponse deviceResponse =
                        OAuthResponse.status(HttpServletResponse.SC_ACCEPTED).setParam(Constants.DEVICE_CODE,
                                deviceCode).setParam(Constants.USER_CODE, userCode).setParam(Constants.VERIFICATION_URI,
                                redirectionUri).setParam(Constants.VERIFICATION_URI_COMPLETE, redirectionUriComplete).
                                setParam(Constants.EXPIRES_IN, String.valueOf(expiresIn / 1000))
                                .setParam(Constants.INTERVAL, String.valueOf(interval / 1000)).buildJSONMessage();
                Response.ResponseBuilder respBuilder = Response.status(response.getStatus());
                return respBuilder.entity(deviceResponse.getBody()).build();

            } else {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

                try {
                    errorResponse = OAuthASResponse
                            .errorResponse(response.getStatus())
                            .setError(ErrorCodes.UNAUTHORIZED_CLIENT)
                            .setErrorDescription("No registered client with the client id.")
                            .buildJSONMessage();

                    Response.ResponseBuilder respBuilder = Response.status(response.getStatus());
                    return respBuilder.entity(errorResponse.getBody()).build();
                } catch (OAuthSystemException e) {

                    if (log.isDebugEnabled()) {
                        log.debug("Error building errorResponse due to:", e);
                    }
                }
            }
        } else {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            try {
                errorResponse = OAuthASResponse
                        .errorResponse(response.getStatus())
                        .setError(ErrorCodes.INVALID_REQUEST)
                        .setErrorDescription("Request missing required parameters")
                        .buildJSONMessage();

                // ResponseHeader[] headers = oauth2AccessTokenResp.getResponseHeaders();
                Response.ResponseBuilder respBuilder = Response.status(response.getStatus());
                return respBuilder.entity(errorResponse.getBody()).build();
            } catch (OAuthSystemException e) {

                if (log.isDebugEnabled()) {
                    log.debug("Error building errorResponse due to:", e);
                }
            }
        }
        return null;
    }

    private boolean validateClientId(String clientId) throws IdentityOAuth2Exception {

        return DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().checkClientIdExist(clientId);
    }
}

