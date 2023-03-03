package org.wso2.carbon.identity.oauth.par.dao;


import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.wso2.carbon.identity.oauth.par.exceptions.ParCoreException;
import org.wso2.carbon.identity.oauth.par.model.ParDataRecord;

import java.io.Serializable;
import java.sql.SQLException;

/**
 * DAO layer for PAR.
 */
public interface ParMgtDAO {

    /**
     * Persists the ParAuthRequest.
     *
     * @param oauthRequest Data object that accumulates  par request data.
     */
    void persistParRequest(String reqUUID, String oauthRequest, long reqMadeAt) throws ParCoreException, SQLException;

    /**
     * Returns ParAuthRequestObject identified by unique UUID of requestUri.
     *
     * @param reqUUID identifier of par request.
     */
    ParDataRecord getParRequestRecord(String reqUUID) throws ParCoreException;

}
