/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.test.common.testng.utils;

import java.lang.reflect.Method;

/**
 * Some White-Box utilities, to call/set internal states with reflection.
 * Mockito and PowerMockito has Witebox class. But seems not quite simple.
 */
public class WhiteBox {

    /**
     * Invokes an internal method with given parameters.
     *
     * @param instance
     * @param methodToExecute
     * @param arguments
     * @param <T>
     * @return
     * @throws Exception
     */
    public static <T> T invokeMethod(Object instance, String methodToExecute, Object... arguments) throws Exception {
        if (instance == null) {
            throw new NoSuchMethodException(
                    "Could not find a method to execute on class null. method " + methodToExecute);
        }

        Class clazz = instance.getClass();
        return invokeMethod(clazz, instance, methodToExecute, arguments);
    }

    /**
     * Invokes an internal method with given parameters.
     * @param clazz
     * @param instance
     * @param methodToExecute
     * @param arguments
     * @param <T>
     * @return
     * @throws Exception
     */
    public static <T> T invokeMethod(Class clazz, Object instance, String methodToExecute, Object... arguments)
            throws Exception {
        Method[] methods = clazz.getDeclaredMethods();
        for (Method m : methods) {
            if (m.getName().equals(methodToExecute)) {
                if (matchArguments(m, arguments)) {
                    m.setAccessible(true);
                    return (T) m.invoke(instance, arguments);
                }
            }
        }
        throw new NoSuchMethodException(
                "Could not find a method :" + methodToExecute + " in class " + clazz + " which accepts arguments : "
                        + arguments);
    }

    /**
     * Matches the arguments to the methods formal argument types.
     * @param m
     * @param arguments
     * @return
     */
    private static boolean matchArguments(Method m, Object[] arguments) {
        if (arguments == null || arguments.length <= 0) {
            return m.getParameterTypes().length == 0;
        }
        return matches(m.getParameterTypes(), arguments);
    }

    /**
     * Matches the arguments to the parameter types.
     * @param parameterTypes
     * @param arguments
     * @return
     */
    private static boolean matches(Class<?>[] parameterTypes, Object[] arguments) {
        if (parameterTypes.length != arguments.length) {
            return false;
        }
        for (int i = 0; i < parameterTypes.length; i++) {
            Class clazzOfArg = arguments[i] == null ? null : arguments[i].getClass();
            if (!parameterTypes[i].isAssignableFrom(clazzOfArg)) {
                return false;
            }
        }
        return true;
    }
}
