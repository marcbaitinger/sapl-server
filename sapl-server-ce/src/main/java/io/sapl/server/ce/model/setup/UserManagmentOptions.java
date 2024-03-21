/*
 * Copyright (C) 2017-2024 Dominic Heutelbeck (dominic@heutelbeck.com)
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.sapl.server.ce.model.setup;

import lombok.Getter;

@Getter
public enum UserManagmentOptions {
    LOCAL("Local"), KEYCLOAK("OAuth2 Keycloak");

    private final String displayName;

    UserManagmentOptions(String displayName) {
        this.displayName = displayName;
    }

    public static UserManagmentOptions getByDisplayName(String displayName) {
        for (UserManagmentOptions datasourceTypes : UserManagmentOptions.values()) {
            if (datasourceTypes.displayName.equals(displayName)) {
                return datasourceTypes;
            }
        }
        return null;
    }
}
