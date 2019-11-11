/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.ciba.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Creates required CibaDAO.
 */
public class CibaDAOFactory {

    private static final Log log = LogFactory.getLog(CibaDAOFactory.class);

    // Implementation of DAO.
    private CibaAuthMgtDAO cibaAuthMgtDAOImpl;

    private CibaDAOFactory() {

        // This factory creates instance of cibaDAOImplementation.
        cibaAuthMgtDAOImpl = CibaAuthMgtDAOImpl.getInstance();
    }

    private static CibaDAOFactory cibaDAOFactoryInstance = new CibaDAOFactory();

    public static CibaDAOFactory getInstance() {

        if (cibaDAOFactoryInstance == null) {

            synchronized (CibaDAOFactory.class) {

                if (cibaDAOFactoryInstance == null) {

                    /* instance will be created at request time */
                    cibaDAOFactoryInstance = new CibaDAOFactory();
                }
            }
        }
        return cibaDAOFactoryInstance;

    }

    /**
     * Manufactures CibaAuthMgtDAO and returns .
     */
    public CibaAuthMgtDAO getCibaAuthMgtDAO() {
        // This returns created instance of cibaDAOImplementation.

        return cibaAuthMgtDAOImpl;
    }

}
