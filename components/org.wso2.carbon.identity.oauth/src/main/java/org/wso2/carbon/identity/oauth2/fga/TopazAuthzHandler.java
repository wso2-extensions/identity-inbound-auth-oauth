package org.wso2.carbon.identity.oauth2.fga;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authz.topaz.handler.core.DirectoryGraphAuthzResponse;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class TopazAuthzHandler implements AccessControlHandler {
    private static final Log LOG = LogFactory.getLog(org.wso2.carbon.identity.application.authz.topaz.handler.topaz.TopazAuthzHandler.class);

    @Override
    public List<String> getAuthorized(List<String> fgaScopes,String userID){
        List<String> authorizedScopes = new ArrayList<>();
        for(String scope: fgaScopes) {
            //String orgId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getOrganizationId();
            AuthorizationRequest request = new AuthorizationRequest();
            String relation = scope.split("_")[1];
            String resource = scope.split("_")[2];
            String resourceType = resource.substring(0,resource.length()-1);
            request.setSubject(new AccessCheckRequestSubject()
                    .id(userID)
                    .type("user"));
            request.setRelation(new AccessCheckRequestRelation()
                    .method(relation));
            request.setResource(new AccessCheckRequestResource()
                    .id(resource)
                    .type(resourceType));
            org.wso2.carbon.identity.application.authz.topaz.handler.topaz.TopazAuthzHandler topazAuthzHandler = new org.wso2.carbon.identity.application.authz.topaz.handler.topaz.TopazAuthzHandler();

            boolean decision = false;
            try {
                decision = topazAuthzHandler.getTopazDirectoryHandler().check(
                        topazAuthzHandler.getObjManagementHandler().createDirectoryRequestObject(
                                request.getSubject().getType(),
                                request.getSubject().getId(),
                                request.getSubject().getRelation(),
                                request.getResource().getType(),
                                request.getResource().getId(),
                                request.getRelation().getMethod()));
            } catch (IllegalArgumentException iAE) {
                LOG.info("Did not receive a Boolean." + iAE.getMessage() + Arrays.toString(iAE.getStackTrace()));
            } catch (Exception e) {
                LOG.info("Error occurred while retrieving the decision." + e.getMessage() + Arrays.toString(e.getStackTrace()));
            }
            if (decision) {
                authorizedScopes.add(scope);
            }
        }
        return authorizedScopes;
    }

//    @Override
//    public List<String> getScopes(AuthorizationRequest authorizationRequest) {
//        String oSubjectId = authorizationRequest.getSubject().getId();
//        String oResourceId = authorizationRequest.getResource().getId();
//        org.wso2.carbon.identity.application.authz.topaz.handler.topaz.TopazAuthzHandler topazAuthzHandler = new org.wso2.carbon.identity.application.authz.topaz.handler.topaz.TopazAuthzHandler();
//        DirectoryGraphAuthzResponse directoryGraphAuthzResponse = topazAuthzHandler.getTopazDirectoryHandler().graph(
//                topazAuthzHandler.getObjManagementHandler().createDirectoryRequestObject(
//                        authorizationRequest.getSubject().getType(),
//                        oSubjectId,
//                        authorizationRequest.getSubject().getRelation(),
//                        authorizationRequest.getResource().getType(),
//                        oResourceId,
//                        authorizationRequest.getRelation().getMethod()));
//        List<Object> results = directoryGraphAuthzResponse.getResults();
//        List<String> authorizedScopes = new ArrayList<>();
//        List<GraphGenerationResponseResults> graphGenerationResponseResults =
//        for (Object result: results){
//            authorizedScopes.add(result.toString().split(",")[1].split(":")[1]+"_view");
//        }
//        return authorizedScopes;
//    }
}
