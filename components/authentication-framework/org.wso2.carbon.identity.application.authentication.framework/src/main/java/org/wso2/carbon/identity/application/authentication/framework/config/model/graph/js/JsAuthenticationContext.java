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

package org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js;

import jdk.nashorn.api.scripting.AbstractJSObject;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;

/**
 * Javascript wrapper for Java level AuthenticationContext.
 * This provides controlled access to AuthenticationContext object via provided javascript native syntax.
 * e.g
 *  var userName = context.currentSubject.subjectIdentifier
 *
 *  instead of
 *  var userName = context.getCurrentSubject().getAuthenticatedSubjectIdentifier()
 *
 * Also it prevents writing an arbitrary values to the respective fields, keeping consistency on runtime AuthenticationContext.
 * @see AuthenticationContext
 */
public class JsAuthenticationContext extends AbstractJSObject {

    private AuthenticationContext wrapped;

    public JsAuthenticationContext(AuthenticationContext wrapped) {
        this.wrapped = wrapped;
    }

    @Override
    public Object getMember(String name) {
        if (wrapped == null) {
            return super.getMember(name);
        }
        switch (name) {
        case "requestedAcr":
            return wrapped.getRequestedAcr();
        case "currentSubject":
            return new JsAuthenticatedUser(wrapped.getCurrentSubject());
        default:
            return super.getMember(name);
        }
    }

    @Override
    public boolean hasMember(String name) {
        if (wrapped == null) {
            return false;
        }
        switch (name) {
        case "requestedAcr":
            return wrapped.getRequestedAcr() != null;
        case "currentSubject":
            return wrapped.getCurrentSubject() != null;
        default:
            return super.hasMember(name);
        }
    }

    @Override
    public void removeMember(String name) {
        if (wrapped == null) {
            super.removeMember(name);
            return;
        }
        switch (name) {
        case "selectedAcr":
            wrapped.setSelectedAcr(null);
            break;
        default:
            super.removeMember(name);
        }
    }

    @Override
    public void setMember(String name, Object value) {
        if (wrapped == null) {
            super.setMember(name, value);
            return;
        }

        switch (name) {
        case "selectedAcr":
            wrapped.setSelectedAcr(String.valueOf(value));
            break;
        default:
            super.removeMember(name);
        }
    }
}
