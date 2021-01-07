/*
 * Copyright 2016-present Open Networking Foundation
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

package org.opencord.olttopology;


import org.onosproject.net.ConnectPoint;

import java.util.Map;

/**
 * Service for configuring the OLT topology collection and for
 * viewing the topology information.
 */
public interface OltTopologyInformationService {

    /**
     * Get a collection of OLT ports and their neighbors.
     *
     * @return OLT Connect points and it's neighbors
     */
    Map<ConnectPoint, OltNeighborInfo> getNeighbours();

    /**
     * Provision Timer for sending LLDP packets to OLT NNI Ports.
     *
     * @param timer Periodicity in minutes for sending out LLDP packet to OLT NNI ports.
     */
    void lldpPeriodicity(int timer);
}
