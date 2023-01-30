package org.wso2.carbon.identity.oauth.endpoint.par;

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestException;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.openidconnect.RequestObjectBuilder;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;

public class ParRequestUtil {
    private static final String REQUEST = "request";
    private static final String REQUEST_URI = "request_uri";

    public static RequestObject buildRequest(OAuthAuthzRequest oauthRequest, OAuth2Parameters oAuth2Parameters)
            throws RequestObjectException, InvalidRequestException {

        RequestObject requestUriRequestObject;
        RequestObjectBuilder requestObjectBuilder;
        String requestObjectType;

        // Check request parameter type
        if (isRequestParameter(oauthRequest)) {
            //return null if request param used
            return null;
        } else if (isRequestUri(oauthRequest)) {
            requestObjectType = REQUEST_URI;
            ParRequestUriRequestObjectBuilder parRequestUriRequestObjectBuilder =
                    new ParRequestUriRequestObjectBuilder();

            // pass request_uri and oauth2 params to build request object
            requestUriRequestObject = parRequestUriRequestObjectBuilder.buildRequestObject(oauthRequest, oAuth2Parameters);
        } else {
            // Unsupported request object type.
            return null;
        }

        return requestUriRequestObject;
    }

    private static boolean isRequestUri(OAuthAuthzRequest oAuthAuthzRequest) {

        return StringUtils.isNotBlank(oAuthAuthzRequest.getParam(REQUEST_URI));
    }

    private static boolean isRequestParameter(OAuthAuthzRequest oAuthAuthzRequest) {

        return StringUtils.isNotBlank(oAuthAuthzRequest.getParam(REQUEST));
    }
}
