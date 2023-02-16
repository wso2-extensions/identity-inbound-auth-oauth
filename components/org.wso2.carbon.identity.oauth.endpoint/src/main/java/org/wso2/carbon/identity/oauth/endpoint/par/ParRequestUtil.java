package org.wso2.carbon.identity.oauth.endpoint.par;

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestException;
import org.wso2.carbon.identity.oauth.endpoint.message.OAuthMessage;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.openidconnect.RequestObjectBuilder;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;

import javax.servlet.http.HttpServletRequest;

public class ParRequestUtil {
    private static final String REQUEST = "request";
    private static final String REQUEST_URI = "request_uri";

    public static OAuth2Parameters buildRequestPrams(OAuthMessage oAuthMessage, OAuth2Parameters oAuth2Parameters)
            throws InvalidRequestException {

        RequestObject requestUriRequestObject;
        RequestObjectBuilder requestObjectBuilder;
        String requestObjectType;

        // Check request parameter type
        if (oAuthMessage.getRequest().getParameterMap().get(REQUEST)!= null) {
            //return null if request param used
            return null;
        } else if (oAuthMessage.getRequest_uri() != null) {
            ParRequestUriRequestObjectBuilder parRequestUriRequestObjectBuilder =
                    new ParRequestUriRequestObjectBuilder();

            // populate oAuthParams with values passed from PAR request
            oAuth2Parameters = parRequestUriRequestObjectBuilder.populateWithParValues(oAuthMessage, oAuth2Parameters);
        } else {
            // Unsupported request object type.
            return null;
        }

        return oAuth2Parameters;
    }

    public static OAuthAuthzRequest buildParOauthRequest( HttpServletRequest request) throws OAuthProblemException, OAuthSystemException {

        return new ParRequestBuilder(request);
    }

    private static boolean isRequestUri(OAuthAuthzRequest oAuthAuthzRequest) {

        return StringUtils.isNotBlank(oAuthAuthzRequest.getParam(REQUEST_URI));
    }

    private static boolean isRequestParameter(OAuthAuthzRequest oAuthAuthzRequest) {

        return StringUtils.isNotBlank(oAuthAuthzRequest.getParam(REQUEST));
    }
}
