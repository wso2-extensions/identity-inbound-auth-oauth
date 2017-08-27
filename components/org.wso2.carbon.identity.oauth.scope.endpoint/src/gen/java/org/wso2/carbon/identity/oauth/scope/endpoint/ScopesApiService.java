package org.wso2.carbon.identity.oauth.scope.endpoint;

import org.wso2.carbon.identity.oauth.scope.endpoint.*;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.*;

import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ErrorDTO;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ScopeToUpdateDTO;

import java.util.List;

import java.io.InputStream;
import org.apache.cxf.jaxrs.ext.multipart.Attachment;

import javax.ws.rs.core.Response;

public abstract class ScopesApiService {
    public abstract Response deleteScope(String name);
    public abstract Response getScope(String name);
    public abstract Response getScopes(Integer startIndex,Integer count);
    public abstract Response isScopeExists(String name);
    public abstract Response registerScope(ScopeDTO scope);
    public abstract Response updateScope(ScopeToUpdateDTO scope,String name);
}

