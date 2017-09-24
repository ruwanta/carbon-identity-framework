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

package org.wso2.carbon.identity.application.authentication.framework.internal.impl;

import org.apache.axiom.om.OMElement;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 *  Holds Extension with OSGI registration.
 *  OSGI components can provide pre-initialized Objects as extensions.
 *  In contrast, FileBasedConfigurationBuilder.getInstance().getExtensions(), will only provide classes initialized with
 *  its default constructor.
 *  This Extension Holder overcomes the limitation of FileBasedConfigurationBuilder.getInstance().getExtensions(),
 *  by allowing OSGI components to contribute extensions
 */
public class ExtensionHolder {

    private static ExtensionHolder instance = new ExtensionHolder();
    private Map<String, List<Object>> readyToUseExtensionsMap = new HashMap<>();
    private Map<String, String> extensionClassNameMap = new HashMap<>();
    private Map<String, Object> selectedExtensionMap = new HashMap<>();

    /**
     * prevents instantiation.
     */
    private ExtensionHolder() {
        OMElement extensionsElem = FileBasedConfigurationBuilder.getInstance()
                .getConfigElement(FrameworkConstants.Config.QNAME_EXTENSIONS);

        if (extensionsElem != null) {
            for (Iterator extChildElems = extensionsElem.getChildElements(); extChildElems.hasNext(); ) {
                OMElement extensionElem = (OMElement) extChildElems.next();
                String className = extensionElem.getText();
                String extensionQName = extensionElem.getLocalName();
                extensionClassNameMap.put(extensionQName, className);
            }
        }
    }

    public <T extends Object> void addExtension(String qName, T extension) {
        List<Object> availableExtensions = readyToUseExtensionsMap.get(qName);
        if (availableExtensions == null) {
            availableExtensions = new ArrayList<>();
            readyToUseExtensionsMap.put(qName, availableExtensions);
        }

        availableExtensions.add(extension);
    }

    public static ExtensionHolder getInstance() {
        return instance;
    }

    public <T> T getExtension(String qName) {
        Object extensionObject = selectedExtensionMap.get(qName);
        if (extensionObject != null) {
            return (T) extensionObject;
        }

        //TODO: Use reflection, similar to  FileBasedConfigurationBuilder.getInstance().getExtension()
        List<Object> readyToUseExtensions = this.readyToUseExtensionsMap.get(qName);
        if (readyToUseExtensions == null || readyToUseExtensions.size() <= 0) {
            return null;
        }

        String className = extensionClassNameMap.get(qName);
        extensionObject = readyToUseExtensions.stream().filter(e -> e.getClass().getName().equals(className)).findAny()
                .orElse(null);
        if (extensionObject != null) {
            selectedExtensionMap.put(qName, extensionObject);
            return (T) extensionObject;
        }
        return null;
    }
}
