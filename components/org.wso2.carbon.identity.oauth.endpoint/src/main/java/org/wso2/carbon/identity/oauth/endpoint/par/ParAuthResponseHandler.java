package org.wso2.carbon.identity.oauth.endpoint.par;


import net.minidev.json.JSONObject;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.endpoint.exception.ParErrorDTO;
import org.wso2.carbon.identity.oauth.par.common.ParConstants;
import org.wso2.carbon.identity.oauth.par.model.ParAuthCodeResponse;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientValidationResponseDTO;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.UUID;

public class ParAuthResponseHandler {

    private static final Log log = LogFactory.getLog(ParAuthResponseHandler.class);
    private static final String ERROR = "error";
    private static final String ERROR_DESCRIPRION = "error_description";

    public Response createAuthResponse(@Context HttpServletResponse response, ParAuthCodeResponse parAuthCodeResponse) {

        String request_uri = "urn:ietf:params:wso2is:request_uri:" + UUID.randomUUID().toString();
        if (log.isDebugEnabled()) {
            log.debug("Setting ExpiryTime for the response to the  request made by client with clientID : " +
                    parAuthCodeResponse.getClientId() + ".");
        }

        response.setContentType(MediaType.APPLICATION_JSON);

        JSONObject parAuthResponse = new JSONObject();
        parAuthResponse.put(ParConstants.EXPIRES_IN, ParConstants.EXPIRES_IN_DEFAULT_VALUE_IN_SEC);
        parAuthResponse.put(ParConstants.REQUEST_URI, request_uri);

        if (log.isDebugEnabled()) {
            log.debug("Creating PAR Authentication response to the request made by client with clientID : " +
                    parAuthCodeResponse.getClientId() + ".");
        }

        Response.ResponseBuilder responseBuilder = Response.status(HttpServletResponse.SC_CREATED);
        if (log.isDebugEnabled()) {
            log.debug("Returning PAR Authentication Response for the request made by client with clientID : " +
                    parAuthCodeResponse.getClientId() + ".");
        }

        parAuthCodeResponse.setRequestUri(request_uri);
        return responseBuilder.entity(parAuthResponse.toString()).build();
    }

    public Response createErrorResponse(OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO) {

        // Create PAR Authentication Error Response.
        if (log.isDebugEnabled()) {
            log.debug("Creating Error Response for PAR Authentication Request.");
        }

        if (oAuth2ClientValidationResponseDTO.getErrorCode().equals(OAuth2ErrorCodes.SERVER_ERROR)) {
            return handleServerException(oAuth2ClientValidationResponseDTO);
        } else {
            return handleClientException(oAuth2ClientValidationResponseDTO);
        }
    }

    //should have method comments
    public Response createErrorResponse(ParErrorDTO parErrorDTO) {

        // Create PAR Authentication Error Response.
        log.debug("Creating Error Response for PAR Authentication Request.");

        if (parErrorDTO.getErrorCode() == parErrorDTO.getErrorCode()) {
            return handleClientException(parErrorDTO);
        } else {
            return null;
        }
    }

    public Response handleServerException(OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO) {

        return null;
    }

    public Response handleClientException(OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO) {

        String errorCode = oAuth2ClientValidationResponseDTO.getErrorCode();
        JSONObject parErrorResponse = new JSONObject();
        parErrorResponse.put(ERROR, oAuth2ClientValidationResponseDTO.getErrorCode());
        parErrorResponse.put(ERROR_DESCRIPRION, oAuth2ClientValidationResponseDTO.getErrorMsg());

        Response.ResponseBuilder responseBuilder;
        if (errorCode.equals(OAuth2ErrorCodes.INVALID_CLIENT)) {
            responseBuilder = Response.status(HttpServletResponse.SC_UNAUTHORIZED);
        } else {
            responseBuilder = Response.status(HttpServletResponse.SC_BAD_REQUEST);
        }
        return responseBuilder.entity(parErrorResponse.toString()).build();
    }

    public Response handleClientException(ParErrorDTO parErrorDTO) {

        JSONObject parErrorResponse = new JSONObject();
        parErrorResponse.put(ERROR, parErrorDTO.getErrorMsg());
        parErrorResponse.put(ERROR_DESCRIPRION, "request.with.request_uri.not.allowed");

        Response.ResponseBuilder responseBuilder;
        responseBuilder = Response.status(HttpServletResponse.SC_BAD_REQUEST);
        return responseBuilder.entity(parErrorResponse.toString()).build();
    }

}
