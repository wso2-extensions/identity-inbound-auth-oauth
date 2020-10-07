package org.wso2.carbon.identity.oauth.common;

import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.utils.OAuthUtils;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ALLOWED_CONTENT_TYPES;

/**
 * Common utility functions for OAuth related operations.
 */
public class OAuthCommonUtil {

    /**
     * Check whether HTTP content type header is an allowed content type.
     *
     * @param contentTypeHeader Content-Type header sent in HTTP request.
     * @param allowedContentTypes Allowed list of content types.
     * @return true if the content type is allowed, else, false.
     */
    public static boolean isAllowedContentType(String contentTypeHeader, List<String> allowedContentTypes) {

        if (contentTypeHeader == null || allowedContentTypes == null) {
            return false;
        }

        String[] requestContentTypes = contentTypeHeader.split(";");
        for (String requestContentType : requestContentTypes) {
            if (allowedContentTypes.contains(requestContentType)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Validate whether the HTTP request's content type are either "application/x-www-form-urlencoded" or
     * "application/json".
     *
     * @param request HTTP request to be validated.
     * @throws OAuthProblemException if HTTP request is has an unsupported content type.
     */
    public static void validateContentTypes(HttpServletRequest request) throws OAuthProblemException {

        String contentType = request.getContentType();
        if (!isAllowedContentType(contentType, ALLOWED_CONTENT_TYPES)) {
            throw OAuthUtils.handleBadContentTypeException(String.join(" or ", ALLOWED_CONTENT_TYPES));
        }
    }
}
