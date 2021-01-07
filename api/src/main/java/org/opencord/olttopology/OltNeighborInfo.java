/*
 * Copyright 2017-present Open Networking Foundation
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

import org.onlab.packet.LLDPTLV;

import org.onosproject.net.Port;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Information about an OLT's neighbor. An instance of this class stores
 * information about an OLT and it's neighbour. The information contains
 * which port of the OLT is connected to which port of the neighbor
 */
public class OltNeighborInfo {

    private String neighborName;
    private String neighborPort;
    private String oltName;
    private Port oltPort;

    // Serial number of the OLT
    private String oltSerialNo;

    // The management IP address of the neighbor
    private String mgmtAddr;

    // The time when this entry was last updated
    private Date lastUpdated;

    // List of other optional TLVs that would have been received from the
    // neighbor in the last LLDP message
    private List<LLDPTLV> otherOptionalTlvs;

    public OltNeighborInfo(String neighborName, String neighborPort,
                           String oltName, Port oltPort, String oltSerialNo) {
        this.neighborName = neighborName;
        this.neighborPort = neighborPort;
        this.oltName = oltName;
        this.oltPort = oltPort;
        this.oltSerialNo = oltSerialNo;
        otherOptionalTlvs = new ArrayList<>();
        updateTimeStamp();
    }

    public String neighborName() {
        return neighborName;
    }

    public String neighborPort() {
        return neighborPort;
    }

    public String oltName() {
        return oltName;
    }

    public Port oltPort() {
        return oltPort;
    }

    public String oltSerialNo() {
        return oltSerialNo;
    }

    public Date getLastUpdated() {
        return lastUpdated;
    }

    public void updateTimeStamp() {
        lastUpdated = new Date();
    }

    public String mgmtAddr() {
        return mgmtAddr;
    }

    public void setMgmtAddress(String neighborManagementAddress) {
        mgmtAddr = neighborManagementAddress;
    }

    public void addOtherOptionalLldpTlvs(LLDPTLV lldptlv) {
        otherOptionalTlvs.add(lldptlv);
    }

    public List<LLDPTLV> getOtherOptionalTlvs() {
        return otherOptionalTlvs;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        OltNeighborInfo that = (OltNeighborInfo) o;
        return Objects.equals(neighborName, that.neighborName) &&
                Objects.equals(neighborPort, that.neighborPort) &&
                Objects.equals(oltName, that.oltName) &&
                Objects.equals(oltPort, that.oltPort) &&
                Objects.equals(oltSerialNo, that.oltSerialNo) &&
                Objects.equals(mgmtAddr, that.mgmtAddr) &&
                Objects.equals(lastUpdated, that.lastUpdated);
    }

    @Override
    public int hashCode() {
        return Objects.hash(neighborName, neighborPort, oltName,
                oltPort, oltSerialNo, mgmtAddr, lastUpdated);
    }

    /*
     * (non-Javadoc)
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        final StringBuilder buf = new StringBuilder();
        buf.append('[');
        buf.append("neighborName:");
        buf.append(this.neighborName);
        buf.append(",neighborPort:");
        buf.append(this.neighborPort);
        buf.append(",oltName:");
        buf.append(this.oltName);
        buf.append(",oltPort:");
        buf.append((this.oltPort.annotations().value("portName").isEmpty()) ? "" :
                this.oltPort.annotations().value("portName"));
        buf.append(",oltSerialNo:");
        buf.append(this.oltSerialNo);
        buf.append(",neighbor_mgmt_address:");
        buf.append(this.mgmtAddr);
        buf.append(",lastUpdated:");
        buf.append(this.lastUpdated);
        buf.append(']');
        return buf.toString();
    }
}
