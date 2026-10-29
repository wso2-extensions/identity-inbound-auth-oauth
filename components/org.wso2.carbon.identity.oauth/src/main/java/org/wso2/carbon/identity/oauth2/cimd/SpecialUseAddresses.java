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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.cimd;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Addresses a server-side fetch must not reach: loopback, private, link-local, shared, multicast, documentation,
 * translation and other special-use ranges (IANA IPv4 and IPv6 special-purpose address registries), plus cloud
 * platform endpoints outside those ranges.
 */
final class SpecialUseAddresses {

    private static final List<Range> RANGES = Collections.unmodifiableList(buildRanges(
            "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
            "192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24",
            "192.168.0.0/16", "192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
            "224.0.0.0/4", "240.0.0.0/4",
            // Azure platform endpoint (WireServer), which is not in a special-use range.
            "168.63.129.16/32",
            // IPv4-mapped IPv6 addresses resolve to Inet4Address, so the IPv4 ranges above cover them.
            // ::/96 also covers the unspecified, loopback and IPv4-compatible addresses.
            "::/96", "::ffff:0:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
            "2001:db8::/32", "2002::/16", "2620:4f:8000::/48", "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10",
            "fec0::/10", "ff00::/8"));

    private SpecialUseAddresses() {

    }

    static boolean isSpecialUse(InetAddress address) {

        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isSiteLocalAddress() || address.isMulticastAddress()) {
            return true;
        }
        byte[] bytes = address.getAddress();
        for (Range range : RANGES) {
            if (range.contains(bytes)) {
                return true;
            }
        }
        return false;
    }

    private static List<Range> buildRanges(String... cidrs) {

        List<Range> ranges = new ArrayList<>(cidrs.length);
        for (String cidr : cidrs) {
            String[] parts = cidr.split("/");
            try {
                // Literal addresses only, so no lookup happens.
                ranges.add(new Range(InetAddress.getByName(parts[0]).getAddress(), Integer.parseInt(parts[1])));
            } catch (UnknownHostException e) {
                throw new IllegalStateException("Invalid special-use range: " + cidr, e);
            }
        }
        return ranges;
    }

    private static final class Range {

        private final byte[] network;
        private final int prefixLength;

        private Range(byte[] network, int prefixLength) {

            this.network = network;
            this.prefixLength = prefixLength;
        }

        private boolean contains(byte[] address) {

            if (address.length != network.length) {
                return false;
            }
            int fullBytes = prefixLength / 8;
            for (int i = 0; i < fullBytes; i++) {
                if (address[i] != network[i]) {
                    return false;
                }
            }
            int remainingBits = prefixLength % 8;
            if (remainingBits == 0) {
                return true;
            }
            int mask = (0xff << (8 - remainingBits)) & 0xff;
            return (address[fullBytes] & mask) == (network[fullBytes] & mask);
        }
    }
}
