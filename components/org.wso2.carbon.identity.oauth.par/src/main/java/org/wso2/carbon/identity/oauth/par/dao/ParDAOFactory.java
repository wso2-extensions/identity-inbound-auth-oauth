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

package org.wso2.carbon.identity.oauth.par.dao;

/**
 * Creates required CibaDAO.
 */
public class ParDAOFactory {

    // Implementation of DAO.
    private ParMgtDAO parMgtDAOImpl;

    private ParDAOFactory() {

        // This factory creates instance of PAR DAOImplementation.
        parMgtDAOImpl = new ParMgtDAOImple();
    }

    private static ParDAOFactory parDAOFactoryInstance = new ParDAOFactory();

    public static ParDAOFactory getInstance() {

        return parDAOFactoryInstance;
    }

    /**
     * @return  ParMgtDAO.
     */
    public ParMgtDAO getParAuthMgtDAO() {

        return parMgtDAOImpl;
    }
}
