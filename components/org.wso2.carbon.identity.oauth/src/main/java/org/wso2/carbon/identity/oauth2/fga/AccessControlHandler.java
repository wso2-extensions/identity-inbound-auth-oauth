package org.wso2.carbon.identity.oauth2.fga;

import java.util.List;

public interface AccessControlHandler {

   List<String> getAuthorized(List<String> fgaScopes, String userID);
//   List<String> getScopes(AuthorizationRequest authorizationRequest);
}