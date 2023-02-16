//package org.wso2.carbon.identity.oauth2.util;
//
//import org.apache.commons.lang.StringUtils;
//import org.apache.commons.logging.Log;
//import org.apache.commons.logging.LogFactory;
//import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
//import org.apache.oltu.oauth2.common.message.OAuthMessage;
//import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
//import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
//import org.wso2.carbon.identity.oauth.common.OAuthConstants;
//import org.wso2.carbon.identity.oauth2.RequestObjectException;
//import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
//import org.wso2.carbon.identity.openidconnect.model.RequestObject;
//
//public class OAuth2RequestObjectUtil {
//
//    private static final Log log = LogFactory.getLog(OAuth2RequestObjectUtil.class);
//    private static final String REQUEST = "request";
//    private static final String REQUEST_URI = "request_uri";
//    private static final String REGEX_PATTERN = "regexp";
//
//
//    public void handleParRequest(OAuthMessage oAuthMessage, OAuthAuthzRequest oauthRequest,
//                                  OAuth2Parameters parameters) throws RequestObjectException, InvalidRequestException {
//
//        String requestObjValue = null;
//        if (isRequestUri(oauthRequest)) {
//            requestObjValue = oauthRequest.getParam(REQUEST_URI);
//            // TODO:
////        } else if (isRequestParameter(oauthRequest)) {
////            requestObjValue = oauthRequest.getParam(REQUEST);
//        }
//
//        if (StringUtils.isNotEmpty(requestObjValue)) {
//            handleParRequestObject(oAuthMessage, oauthRequest, parameters);
//        } else {
//            if (log.isDebugEnabled()) {
//                log.debug("Authorization Request does not contain a Request Object or Request Object reference.");
//            }
//        }
//    }
//
//    private void handleParRequestObject(OAuthMessage oAuthMessage, OAuthAuthzRequest oauthRequest,
//                                               OAuth2Parameters parameters)
//            throws RequestObjectException, InvalidRequestException {
//
//        ParRequestBuilderUtil parRequestBuilderUtil = new ParRequestBuilderUtil();
//
//        RequestObject requestObject = parRequestBuilderUtil.buildRequest(oauthRequest, parameters);
//        if (requestObject == null) {
//            throw new RequestObjectException(OAuth2ErrorCodes.INVALID_REQUEST, "Unable to build a valid Request " +
//                    "Object from the authorization request.");
//        }
//
//        // If the redirect uri was not given in auth request the registered redirect uri will be available here,
//        // so validating if the registered redirect uri is a single uri that can be properly redirected.
//        if (StringUtils.isBlank(parameters.getRedirectURI()) ||
//                StringUtils.startsWith(parameters.getRedirectURI(), REGEX_PATTERN)) {
//            LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, null,
//                    OAuthConstants.LogConstants.FAILED, "Redirect URI is not present in the authorization request.",
//                    "validate-input-parameters", null);
//            throw new InvalidRequestException("Redirect URI is not present in the authorization request.",
//                    OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ErrorCodes.OAuth2SubErrorCodes.INVALID_REDIRECT_URI);
//        }
//    }
//
//
//    private static boolean isRequestUri(OAuthAuthzRequest oAuthAuthzRequest) {
//
//        String param = oAuthAuthzRequest.getParam(REQUEST_URI);
//        return StringUtils.isNotBlank(param);
//    }
//
//    private static boolean isRequestParameter(OAuthAuthzRequest oAuthAuthzRequest) {
//
//        String param = oAuthAuthzRequest.getParam(REQUEST);
//        return StringUtils.isNotBlank(param);
//    }
//}
