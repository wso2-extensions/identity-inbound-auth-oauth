package org.wso2.carbon.identity.oauth2.dto;

import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

public class TokenBindingDTO {
    String freshToken;
    String boundToken;
    HttpRequestHeader[] httpRequestHeaders;
    OAuthTokenReqMessageContext tokReqMsgCtx;
    OAuthAuthzReqMessageContext oauthAuthzMsgCtx;
    String tokenBindingHash;
    String delimiter ="@%$";

    public void setFreshToken(String freshToken) {
        this.freshToken = freshToken;
    }

    public void setBoundToken(String boundToken) {
        this.boundToken = boundToken;
    }

    public void setHttpRequestHeaders(HttpRequestHeader[] httpRequestHeaders) {
        this.httpRequestHeaders = httpRequestHeaders;
    }

    public void setTokReqMsgCtx(OAuthTokenReqMessageContext tokReqMsgCtx) {
        this.tokReqMsgCtx = tokReqMsgCtx;
    }

    public void setOauthAuthzMsgCtx(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) {
        this.oauthAuthzMsgCtx = oauthAuthzMsgCtx;
    }

    public void setTokenBindingHash(String tokenBindingHash) {
        this.tokenBindingHash = tokenBindingHash;
    }

    public void changeDefaultSeperator(String delimiter) {
        this.delimiter = delimiter;
    }

    public String unbind(String token){
        return OAuth2Util.decodeBase64ThenSplit(token,";");

    }
}
