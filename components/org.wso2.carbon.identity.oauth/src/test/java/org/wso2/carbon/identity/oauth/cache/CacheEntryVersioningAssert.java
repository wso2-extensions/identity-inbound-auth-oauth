/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.cache;

import org.nustaq.serialization.annotations.Version;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Reusable assertion helper that enforces the FST serialization-compatibility contract on classes
 * extending {@code org.wso2.carbon.identity.core.cache.CacheEntry}:
 * <ul>
 *   <li>Every field declared at the time versioning was introduced (the "v0 baseline") must still
 *       exist, in the SAME declaration order, and must NOT carry {@code @Version}.</li>
 *   <li>Every field declared outside the baseline must carry {@code @Version(n)} with n >= 1 and
 *       must appear AFTER all baseline fields in source declaration order.</li>
 *   <li>The total number of {@code @Version}-annotated fields must match the expected count, so
 *       deletion of a versioned field is also caught.</li>
 * </ul>
 * The helper is class-agnostic — callers supply the target class and its frozen baseline.
 *
 * <p>Note on declaration order: {@code Class#getDeclaredFields()} does not formally guarantee
 * source order, but all mainstream JVMs (HotSpot/OpenJDK) return fields in declaration order, and
 * FST's own versioning contract relies on that same ordering, so this assertion is consistent
 * with the runtime behaviour the cache entries depend on.</p>
 */
final class CacheEntryVersioningAssert {

    private CacheEntryVersioningAssert() {
    }

    static void assertFieldVersioning(Class<?> target, List<String> v0Baseline, int expectedVersionedCount) {

        List<String> violations = new ArrayList<>();
        List<Field> declared = declaredInstanceFields(target);
        Set<String> declaredNames = new HashSet<>();
        for (Field f : declared) {
            declaredNames.add(f.getName());
        }

        int baselineLimit = Math.min(v0Baseline.size(), declared.size());
        for (int i = 0; i < baselineLimit; i++) {
            Field field = declared.get(i);
            String expected = v0Baseline.get(i);
            String actual = field.getName();
            if (!actual.equals(expected)) {
                violations.add("Field at declaration position " + i + " is '" + actual +
                        "' but the v0 baseline expects '" + expected +
                        "'. Baseline fields must retain their original declaration order — " +
                        "reordering, renaming, or inserting unversioned fields breaks FST deserialization " +
                        "of previously persisted entries.");
            }
            if (field.isAnnotationPresent(Version.class)) {
                violations.add("Baseline field '" + actual + "' must NOT carry @Version. " +
                        "Baseline fields are the pre-versioning snapshot; do not retrofit @Version on them.");
            }
        }

        int versionedCount = 0;
        for (int i = v0Baseline.size(); i < declared.size(); i++) {
            Field field = declared.get(i);
            String name = field.getName();
            if (!field.isAnnotationPresent(Version.class)) {
                violations.add("Field '" + name + "' at declaration position " + i +
                        " is declared after the v0 baseline but does not carry @Version. " +
                        "Every new field added to " + target.getSimpleName() +
                        " MUST be annotated with @Version(n) and appended after all baseline fields.");
            } else {
                versionedCount++;
                int v = field.getAnnotation(Version.class).value();
                if (v < 1) {
                    violations.add("Field '" + name + "' has @Version(" + v + "); value must be >= 1.");
                }
            }
        }

        for (String expected : v0Baseline) {
            if (!declaredNames.contains(expected)) {
                violations.add("Baseline field '" + expected + "' is missing from " + target.getSimpleName() +
                        ". Existing fields must never be removed or renamed — doing so breaks deserialization " +
                        "of cache entries already persisted in IDN_AUTH_SESSION_STORE.");
            }
        }

        if (versionedCount != expectedVersionedCount) {
            violations.add("Expected " + expectedVersionedCount + " @Version-annotated field(s) on " +
                    target.getSimpleName() + " but found " + versionedCount +
                    ". If this change is intentional, update the expected count in the test's data provider.");
        }

        if (!violations.isEmpty()) {
            StringBuilder msg = new StringBuilder("FST versioning contract violated on ")
                    .append(target.getName()).append(':');
            for (String v : violations) {
                msg.append("\n  - ").append(v);
            }
            throw new AssertionError(msg.toString());
        }
    }

    static void assertBaselinePresent(Class<?> target, List<String> v0Baseline) {

        List<String> declaredOrder = new ArrayList<>();
        for (Field field : declaredInstanceFields(target)) {
            declaredOrder.add(field.getName());
        }
        Set<String> declaredSet = new HashSet<>(declaredOrder);

        List<String> missing = new ArrayList<>();
        for (String expected : v0Baseline) {
            if (!declaredSet.contains(expected)) {
                missing.add(expected);
            }
        }
        if (!missing.isEmpty()) {
            throw new AssertionError("Baseline fields missing from " + target.getName() + ": " + missing +
                    ". Renaming/removing these fields breaks FST deserialization of previously persisted entries.");
        }

        int baselineLimit = Math.min(v0Baseline.size(), declaredOrder.size());
        List<String> orderViolations = new ArrayList<>();
        for (int i = 0; i < baselineLimit; i++) {
            String expected = v0Baseline.get(i);
            String actual = declaredOrder.get(i);
            if (!actual.equals(expected)) {
                orderViolations.add("position " + i + ": expected '" + expected + "', found '" + actual + "'");
            }
        }
        if (!orderViolations.isEmpty()) {
            throw new AssertionError("Baseline field order drift on " + target.getName() + ": " +
                    orderViolations + ". Baseline fields must retain their original declaration order.");
        }
    }

    private static List<Field> declaredInstanceFields(Class<?> target) {

        List<Field> result = new ArrayList<>();
        for (Field field : target.getDeclaredFields()) {
            if (!isIgnored(field)) {
                result.add(field);
            }
        }
        return Collections.unmodifiableList(result);
    }

    private static boolean isIgnored(Field field) {

        int mods = field.getModifiers();
        if (Modifier.isStatic(mods) || Modifier.isTransient(mods)) {
            return true;
        }
        if (field.isSynthetic()) {
            return true;
        }
        String name = field.getName();
        return name.startsWith("$") || "serialVersionUID".equals(name);
    }
}
