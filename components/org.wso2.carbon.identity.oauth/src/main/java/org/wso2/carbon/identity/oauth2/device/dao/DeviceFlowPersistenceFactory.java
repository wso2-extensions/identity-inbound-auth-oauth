package org.wso2.carbon.identity.oauth2.device.dao;

public class DeviceFlowPersistenceFactory {

    private static DeviceFlowPersistenceFactory factory;
    private DeviceFlowDAO deviceFlowDAO;

    public DeviceFlowPersistenceFactory(){
        this.deviceFlowDAO = new DeviceFlowDAOImpl();
    }

    public static DeviceFlowPersistenceFactory getInstance() {

        if (factory == null) {
            factory = new DeviceFlowPersistenceFactory();
        }
        return factory;
    }

    public DeviceFlowDAO getDeviceFlowDAO() {
        return deviceFlowDAO;
    }

}
