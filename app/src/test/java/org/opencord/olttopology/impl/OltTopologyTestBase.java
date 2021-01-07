/*
 * Copyright 2018-present Open Networking Foundation
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

import org.apache.commons.lang.ArrayUtils;
import org.onlab.packet.BasePacket;
import org.onlab.packet.Ethernet;
import org.onlab.packet.EthType;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.LLDP;
import org.onlab.packet.LLDPTLV;
import org.onlab.packet.MacAddress;


import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthTypeCriterion;
import org.onosproject.net.flowobjective.FilteringObjective;
import org.onosproject.net.flowobjective.FlowObjectiveServiceAdapter;
import org.onosproject.net.packet.DefaultInboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.DefaultPacketContext;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketServiceAdapter;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.notNullValue;

import org.opencord.olttopology.OltNeighborInfo;
import org.slf4j.Logger;

import static org.junit.Assert.assertThat;

import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.fail;


import static org.slf4j.LoggerFactory.getLogger;

/*
Olt topology test base class.
 */
public class OltTopologyTestBase {
    private final Logger log = getLogger(getClass());

    //Time in ms to wait before checking packets
    static final int ASSERTION_DELAY = 250;
    //Duration in ms of the assertion for packets
    static final int ASSERTION_LENGTH = 250;

    private static final String EXPECTED_IP = "10.10.10.10";
    private static final String EXPECTED_OLT_DEV_ID = "of:0000c6b1cd40dc93";
    private static final DeviceId EXPECTED_DEVICE_ID_1 = DeviceId.deviceId(EXPECTED_OLT_DEV_ID);



    List<BasePacket> savedPackets = new LinkedList<>();
    PacketProcessor packetProcessor;
    MacAddress srcMac = MacAddress.valueOf("c6:b1:cd:40:dc:93");
    MacAddress dstMac = MacAddress.valueOf(OsgiPropertyConstants.DEFAULT_DEST_MAC_ADDRESS_DEFAULT);


    /**
     * Saves the given packet onto the saved packets list.
     *
     * @param packet packet to save
     */
    void savePacket(BasePacket packet) {
        savedPackets.add(packet);
    }

    /**
     * Sends packet to Packer process to test Handle packet functionality.
     * @param packet LLDP ethernet packet
     * @param cp Device connect point info
     */
    void sendInboundPacket(Ethernet packet, ConnectPoint cp) {
        final ByteBuffer byteBuffer = ByteBuffer.wrap(packet.serialize());
        InboundPacket inPacket = new DefaultInboundPacket(cp, packet, byteBuffer);
        PacketContext context = new TestPacketContext(127L, inPacket, null, false);
        packetProcessor.process(context);
    }

    /**
     * Validates LLDP packet out functionality.
     * @param responsePacket LLDP packet
     */
    void checkLldpPacket(Ethernet responsePacket) {
     assertThat(responsePacket.getSourceMAC(), is(srcMac));
     assertThat(responsePacket.getDestinationMAC(), is(dstMac));
     assertThat(responsePacket.getPayload(), instanceOf(LLDP.class));
     assertThat(responsePacket.getEtherType(), is(Ethernet.TYPE_LLDP));
     LLDP lldp = (LLDP) responsePacket.getPayload();
     assertThat(lldp, notNullValue());
     assertThat(lldp.getPortId(), notNullValue());
     String portName = "nni-";
     byte[] port  = ArrayUtils.addAll(new byte[] {5}, portName.getBytes());
     assertThat(lldp.getPortId().getValue(), is(port));
     assertThat(lldp.getChassisId(), notNullValue());
     int chassisId = 0;
     byte[] chassis = ArrayUtils.addAll(new byte[] {1},
             ByteBuffer.allocate(String.valueOf(chassisId).length())
                     .put(String.valueOf(chassisId).getBytes()).array());
     assertThat(lldp.getChassisId().getValue(), is(chassis));
     assertThat(lldp.getTtl().getValue(), notNullValue());
     short ttl = 120;
     byte[] time = ByteBuffer.allocate(2).putShort(ttl).array();
     assertThat(lldp.getTtl().getValue(), is(time));
     assertThat(lldp.getOptionalTLVList(), notNullValue());
     List<LLDPTLV> optionalTlvs = lldp.getOptionalTLVList();
     for (LLDPTLV tlv: optionalTlvs) {
         if (tlv.getType() == OltTopology.SYSTEMNAME_TLV_TYPE) {
             assertThat(tlv.getValue(), notNullValue());
             String[] systemName = EXPECTED_DEVICE_ID_1.toString().split(":", 2);
             byte[] deviceId = systemName[1].getBytes();
             assertThat(tlv.getValue(), is(deviceId));
         } else if (tlv.getType() == OltTopology.MANAGEMENT_ADDR_TLV_TYPE) {
             assertThat(tlv.getValue(), notNullValue());
             final byte ipAddressSubType = 0x1; // IPv4
             // 5 below is address subtype + IP4 address len
             final byte ipAddrStrLen = 0x5;
             final byte interfaceSubtype = 0x1;
             final int interfaceNum = 0;
             final byte oidString = 0x0;
             Ip4Address ipAddr = Ip4Address.valueOf(EXPECTED_IP);

             byte[] addrStr =  ArrayUtils.addAll(new byte[] {ipAddressSubType},
                     ipAddr.toOctets());

             byte[] ipAddrBytes =  ArrayUtils.addAll(new byte[] {ipAddrStrLen},
                     addrStr);
             byte[] bytesInterfacetype = ArrayUtils.addAll(ipAddrBytes,
                     ByteBuffer.allocate(1).put(interfaceSubtype).array());
             byte[] bytesInterfaceNumber = ArrayUtils.addAll(bytesInterfacetype,
                     ByteBuffer.allocate(4).putInt(interfaceNum).array());
             byte[] finalMgmtAddrBytes = ArrayUtils.addAll(bytesInterfaceNumber,
                     ByteBuffer.allocate(1).put(oidString).array());
             assertThat(tlv.getValue(), is(finalMgmtAddrBytes));

         }
     }
    }

    /**
     * Validates Neightbour list table.
     * @param neighborList Neighbour list table created using inbound LLDP packets.
     */
    void validateNeighborList(Map<ConnectPoint, OltNeighborInfo> neighborList) {
        assertThat(neighborList, notNullValue());
        assertThat(neighborList.size(), is(1));
        for (Map.Entry<ConnectPoint, OltNeighborInfo> entry: neighborList.entrySet()) {
            assertThat(entry.getValue().mgmtAddr(), is("192.168.1.1"));
            assertThat(entry.getValue().neighborName(), is("switch-1"));
            assertThat(entry.getValue().neighborPort(), is("p0"));
            assertThat(entry.getValue().oltName(), is("0000c6b1cd40dc93"));
            assertThat(entry.getValue().oltPort().annotations().value("portName"), is("nni-"));
        }
    }
    /**
     * Keeps a reference to the PacketProcessor and saves the OutboundPackets.
     */
    class MockPacketService extends PacketServiceAdapter {

        @Override
        public void addProcessor(PacketProcessor processor, int priority) {
            packetProcessor = processor;
        }

        @Override
        public void emit(OutboundPacket packet) {
            try {
                Ethernet eth = Ethernet.deserializer().deserialize(packet.data().array(),
                        0, packet.data().array().length);
                savePacket(eth);
            } catch (Exception e) {
                fail(e.getMessage());
            }
        }
    }
    /**
     * Mock Flow Objective Service.
     */
    public static class MockFlowObjectiveService extends FlowObjectiveServiceAdapter {

        @Override
        public void filter(DeviceId deviceId, FilteringObjective filter) {
            assertThat(deviceId, notNullValue());
            assertThat(filter, notNullValue());
            EthTypeCriterion ethType = (EthTypeCriterion)
                    filterForCriterion(filter.conditions(), Criterion.Type.ETH_TYPE);
            assertThat(ethType, notNullValue());
            assertThat(ethType.ethType(), is(EthType.EtherType.LLDP.ethType()));
            assertThat(filter.key().type(), is(Criterion.Type.IN_PORT));

        }
        private Criterion filterForCriterion(Collection<Criterion> criteria, Criterion.Type type) {
            return criteria.stream()
                    .filter(c -> c.type().equals(type))
                    .limit(1)
                    .findFirst().orElse(null);
        }

    }
    /**
     * Mocks the DefaultPacketContext.
     */
    static final class TestPacketContext extends DefaultPacketContext {

        private TestPacketContext(long time, InboundPacket inPkt,
                                  OutboundPacket outPkt, boolean block) {
            super(time, inPkt, outPkt, block);
        }

        @Override
        public void send() {
            // We don't send anything out.
        }
    }
}
