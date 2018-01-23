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

/**
 * This factory class is used to invoke the request object related DAO classes.
 */
public class RequestObjectPersistenceFactory {

    private static RequestObjectPersistenceFactory factory;
    private RequestObjectDAO requestObjectDAO;

    public RequestObjectPersistenceFactory() {
        this.requestObjectDAO = new RequestObjectDAOImpl();
    }

    /**
     * To get an instance of RequestObjectPersistenceFactory.
     * @return an instance of RequestObjectPersistenceFactory
     */
    public static RequestObjectPersistenceFactory getInstance() {

        if (factory == null) {
            factory = new RequestObjectPersistenceFactory();
        }
        return factory;
    }

    public RequestObjectDAO getRequestObjectDAO(){
        return requestObjectDAO;
    }
}
