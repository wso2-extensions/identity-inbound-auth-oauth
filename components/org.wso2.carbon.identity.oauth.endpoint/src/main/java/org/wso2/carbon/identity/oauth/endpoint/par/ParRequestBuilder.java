package org.wso2.carbon.identity.oauth.endpoint.par;

import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.apache.oltu.oauth2.as.request.OAuthRequest;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.validators.OAuthValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;


public class ParRequestBuilder extends OAuthAuthzRequest{

    private Logger log = LoggerFactory.getLogger(OAuthRequest.class);
    protected HttpServletRequest request;
    protected OAuthValidator<HttpServletRequest> validator;
    protected Map<String, Class<? extends OAuthValidator<HttpServletRequest>>> validators = new HashMap();
    private OAuthAuthzRequest parOAuthRequest;


    public ParRequestBuilder(HttpServletRequest request) throws OAuthSystemException, OAuthProblemException {

        super(request);
    }















    public void validateParRequest() throws OAuthProblemException, OAuthSystemException {


//        OAuthAuthzRequest oAuthAuthzRequest;
//
//        String oauthAuthzRequestClassName = OAuthServerConfiguration.getInstance().getOAuthAuthzRequestClassName();
//        if (OAuthServerConfiguration.DEFAULT_OAUTH_AUTHZ_REQUEST_CLASSNAME.equals(oauthAuthzRequestClassName)) {
//            oAuthAuthzRequest = new CarbonOAuthAuthzRequest(request);
//            return oAuthAuthzRequest;
//        }
    }

}
