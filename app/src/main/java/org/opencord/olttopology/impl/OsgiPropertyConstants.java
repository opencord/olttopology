/*
 * Copyright 2019-present Open Networking Foundation
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

package org.opencord.olttopology.impl;

/**
 * Constants for default values of configurable properties.
 */
public final class OsgiPropertyConstants {
    public static final String DEFAULT_DEST_MAC_ADDRESS = "destMacAddress";
    // Destination Mac address where LLDP packet has to be sent.
    public static final String DEFAULT_DEST_MAC_ADDRESS_DEFAULT = "01:80:c2:00:00:00";
    public static final String DEFAULT_TTL_IN_SECS = "ttlInSecs";
    // Default Time To Live value to be used in the LLDP packets sent out
    public static final int DEFAULT_TTL_IN_SECS_DEFAULT = 120;
    public static final String DEFAULT_CHASSIS_ID = "chassisId";
    // Default ChassisId to be used in the LLDP packets sent out
    public static final int DEFAULT_CHASSIS_ID_DEFAULT = 0;
    // Default periodicity (in minutes) of sending the LLDP messages through OLT NNI Ports
    public static final int DEFAULT_LLDP_SEND_PERIODICITY = 15;
    public static final String LLDP_SEND_PERIODICITY_STR = "lldpSendPeriodicity";

    private OsgiPropertyConstants() {
    }
}
