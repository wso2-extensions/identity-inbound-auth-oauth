package org.wso2.carbon.identity.oauth.endpoint.par;

import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestException;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.openidconnect.RequestObjectBuilder;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;

import static org.wso2.carbon.identity.oauth.endpoint.par.RequestUriValidator.isValidRequestUri;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;

public class ParRequestUriRequestObjectBuilder {

    private static final String REQUEST = "request";
    private static final String REQUEST_URI = "request_uri";
    public RequestObject buildRequestObject(OAuthAuthzRequest request, OAuth2Parameters oAuth2Parameters) throws InvalidRequestException{
        Map<String, Map<String, String[]>> parRequestUriRequests = ParRequestData.getRequests();

        RequestObject requestObject = new RequestObject();

        if (isValidRequestUri(request.getParam(REQUEST_URI))){
            oAuth2Parameters.setClientId(request.getClientId());
            oAuth2Parameters.setRedirectURI(parRequestUriRequests.get(request.getParam(REQUEST_URI)).get("redirect_uri")[0]);
            oAuth2Parameters.setResponseType(parRequestUriRequests.get(request.getParam(REQUEST_URI)).get("response_type")[0]);
            oAuth2Parameters.setScopes(new HashSet<String>(Arrays.asList(parRequestUriRequests.get(request.getParam(REQUEST_URI)).get("scope"))));
        }

        return requestObject;
    }
}
