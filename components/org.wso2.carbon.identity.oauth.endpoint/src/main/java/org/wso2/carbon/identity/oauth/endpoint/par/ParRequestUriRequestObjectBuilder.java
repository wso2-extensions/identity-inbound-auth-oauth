package org.wso2.carbon.identity.oauth.endpoint.par;

import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestException;
import org.wso2.carbon.identity.oauth.endpoint.message.OAuthMessage;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;

import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.oauth.endpoint.par.RequestUriValidator.isValidRequestUri;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;

public class ParRequestUriRequestObjectBuilder {

    private static final String REQUEST = "request";
    private static final String REQUEST_URI = "request_uri";
    public OAuth2Parameters populateWithParValues(OAuthMessage oAuthMessage, OAuth2Parameters oAuth2Parameters) throws InvalidRequestException{
        Map<String, Map<String, String[]>> parRequestUriRequests = ParRequestData.getRequests();

        HttpServletRequest request = oAuthMessage.getRequest();

        if (isValidRequestUri(request.getParameter(REQUEST_URI))){
            oAuth2Parameters.setClientId(request.getParameterMap().get("client_id")[0]);
            oAuth2Parameters.setRedirectURI(parRequestUriRequests.get(request.getParameter(REQUEST_URI)).get("redirect_uri")[0]);
            oAuth2Parameters.setResponseType(parRequestUriRequests.get(request.getParameter(REQUEST_URI)).get("response_type")[0]);
            oAuth2Parameters.setScopes(new HashSet<String>(Arrays.asList(parRequestUriRequests.get(request.getParameter(REQUEST_URI)).get("scope"))));
        }

        return oAuth2Parameters;
    }
}
