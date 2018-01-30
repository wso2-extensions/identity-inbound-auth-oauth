/*
 *
 *   Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 * /
 */

package org.wso2.carbon.identity.openidconnect.dao;

import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.openidconnect.model.RequestedClaim;

import java.util.ArrayList;
import java.util.List;

/**
 * This class contains unit tests for RequestObjectDAOImplTest..
 */

@WithCarbonHome
@WithH2Database(jndiName = "jdbc/WSO2IdentityDB",
        files = {"dbScripts/h2_with_application_and_token.sql", "dbScripts/identity.sql"})
public class RequestObjectDAOImplTest {

    @Test
    private void testInsertRequestObject() throws IdentityOAuth2Exception {

        RequestObjectDAO requestObjectDAO = new RequestObjectDAOImpl();
        List<List<RequestedClaim>> requestedEssentialClaims = new ArrayList<>();
        List<RequestedClaim> lstRequestedCliams = new ArrayList<>();
        List<String> values = new ArrayList<>();

        RequestedClaim requestedClaim = new RequestedClaim();
        requestedClaim.setName("email");
        requestedClaim.setType("userinfo");
        requestedClaim.setValue("value1");
        requestedClaim.setEssential(true);
        requestedClaim.setValues(values);
        values.add("val1");
        values.add("val2");
        requestedClaim.setValues(values);
        lstRequestedCliams.add(requestedClaim);
        requestedEssentialClaims.add(lstRequestedCliams);

        requestObjectDAO.insertRequestObjectData("consumerKey", "d43e8da324a33bdc941b9b95cad6a6a2",
                requestedEssentialClaims);
        requestObjectDAO.getRequestedClaims("d43e8da324a33bdc941b9b95cad6a6a2", true);
        Assert.assertEquals(requestObjectDAO.getRequestedClaims("code1", true).size(), 0);
    }
}