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

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import org.apache.commons.lang.ArrayUtils;
import org.easymock.EasyMock;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.onlab.osgi.ComponentContextAdapter;
import org.onlab.packet.ChassisId;
import org.onlab.packet.Ethernet;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.LLDP;
import org.onlab.packet.LLDPTLV;
import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.codec.CodecService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreServiceAdapter;
import org.onosproject.mastership.MastershipServiceAdapter;
import org.onosproject.net.AnnotationKeys;
import org.onosproject.net.Annotations;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DefaultAnnotations;
import org.onosproject.net.DefaultDevice;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Element;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceServiceAdapter;
import org.onosproject.net.provider.ProviderId;
import org.onosproject.store.service.TestStorageService;
import org.opencord.sadis.BaseInformationService;
import org.opencord.sadis.SadisService;
import org.opencord.sadis.SubscriberAndDeviceInformation;
import org.opencord.sadis.UniTagInformation;
import org.slf4j.Logger;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.onosproject.net.intent.TestTools.assertAfter;
import static org.opencord.olttopology.impl.OltTopology.SYSTEMNAME_TLV_TYPE;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Tests OLT topology app.
 */
public class OltTopologyTest extends OltTopologyTestBase {
    private static final VlanId CLIENT_C_TAG = VlanId.vlanId((short) 999);
    private static final VlanId CLIENT_S_TAG = VlanId.vlanId((short) 111);
    private static final String CLIENT_NAS_PORT_ID = "PON 1/1";
    private static final String CLIENT_CIRCUIT_ID = "CIR-PON 1/1";
    private static final String OLT_DEV_ID = "of:0000c6b1cd40dc93";
    private static final MacAddress OLT_MAC_ADDRESS = MacAddress.valueOf("01:02:03:04:05:06");
    private static final DeviceId DEVICE_ID_1 = DeviceId.deviceId(OLT_DEV_ID);
    private static final String SCHEME_NAME = "olttopology";
    private static final DefaultAnnotations DEVICE_ANNOTATIONS = DefaultAnnotations.builder()
            .set(AnnotationKeys.PROTOCOL, SCHEME_NAME.toUpperCase()).build();
    private final Logger log = getLogger(getClass());
    ComponentConfigService mockConfigService =
            EasyMock.createMock(ComponentConfigService.class);
    CodecService mockCodecService =
            EasyMock.createMock(CodecService.class);
    private OltTopology oltTopology;
    private NetworkConfigListener configListener;
    private DeviceListener deviceListener;

    @Before
    public void setUp() {
        oltTopology = new OltTopology();
        oltTopology.mastershipService = new MockMastershipService();
        oltTopology.deviceService = new MockDeviceService();
        oltTopology.coreService = new MockCoreService();
        oltTopology.componentConfigService = mockConfigService;
        oltTopology.packetService = new MockPacketService();
        oltTopology.flowObjectiveService = new MockFlowObjectiveService();
        oltTopology.storageService = new TestStorageService();
        oltTopology.codecService = mockCodecService;
        oltTopology.subsService = new MockSubService();
        oltTopology.sadisService = new MockSadisService();
        oltTopology.subsService.get(OLT_DEV_ID).setUplinkPort(1);
        oltTopology.activate(new ComponentContextAdapter());
    }

    @After
    public void tearDown() {
        oltTopology.deactivate();

    }

    private DeviceEvent deviceEvent(DeviceEvent.Type type, DeviceId did, Port port) {
        return new DeviceEvent(type, oltTopology.deviceService.getDevice(did), port);

    }

    /**
     * Fetches the sent packet at the given index. The requested packet
     * must be the last packet on the list.
     *
     * @param index index into sent packets array
     * @return packet
     */
    private Ethernet fetchPacket(int index) {
        for (int iteration = 0; iteration < 20; iteration++) {
            if (savedPackets.size() > index) {
                return (Ethernet) savedPackets.get(index);
            } else {
                try {
                    Thread.sleep(250);
                } catch (Exception ex) {
                    return null;
                }
            }
        }
        return null;
    }

    /**
     * Testing Port Added Scenario.
     * Note: Need to See second packet as first will be sent when MockPort is called
     *
     */
    @Test
    public void testPortAdded() {
        Device d = oltTopology.deviceService.getDevice(DEVICE_ID_1);
        Port port = new MockPort();
        DeviceEvent portAdd = deviceEvent(DeviceEvent.Type.PORT_ADDED, DEVICE_ID_1, port);
        deviceListener.event(portAdd);
        Ethernet responsePacket = fetchPacket(1);
        assertThat(responsePacket, notNullValue());
        checkLldpPacket(responsePacket);
    }

    /**
     * Testing Port Delete Scenario.
     *
     */
    @Test
    public void testPortDeleted() {
        Device d = oltTopology.deviceService.getDevice(DEVICE_ID_1);
        Port port = new MockPort();
        DeviceEvent portAdd = deviceEvent(DeviceEvent.Type.PORT_ADDED, DEVICE_ID_1, port);
        deviceListener.event(portAdd);
        Ethernet responsePacket = fetchPacket(1);
        assertThat(responsePacket, notNullValue());
        checkLldpPacket(responsePacket);
        DeviceEvent portRem = deviceEvent(DeviceEvent.Type.PORT_REMOVED, DEVICE_ID_1, port);
        deviceListener.event(portRem);
    }

    /**
     * Tests LLDP packet in scenario.
     *
     */
    @Test
    public void testHandlePacket() {
        Device d = oltTopology.deviceService.getDevice(DEVICE_ID_1);
        Port port = new MockPort();
        DeviceEvent portAdd = deviceEvent(DeviceEvent.Type.PORT_ADDED, DEVICE_ID_1, port);
        deviceListener.event(portAdd);
        MacAddress destMac = MacAddress.valueOf(OsgiPropertyConstants.DEFAULT_DEST_MAC_ADDRESS_DEFAULT);
        MacAddress srcMac = MacAddress.valueOf("c6:b1:cd:40:dc:93");
        String serialNumber = "switch-1";
        final short ttlInSec = 120;
        final short chasisId = 0;
        String portName = "p0";
        Ip4Address devIpAddr = Ip4Address.valueOf("192.168.1.1");
        Ethernet packet = createLldpPacket(destMac, srcMac, chasisId, portName,
                ttlInSec, serialNumber, devIpAddr.toString());

        ConnectPoint cp = new ConnectPoint(d.id(), port.number());
        sendInboundPacket(packet, cp);

        assertAfter(ASSERTION_DELAY, ASSERTION_LENGTH, () -> {
            validateNeighborList(oltTopology.getNeighbours());
        });
    }

    /**
     * Tests Packet out timer functionality.
     *
     * @throws Exception
     */
    @Test
    public void testOltTopologyTimerTask() throws Exception {
        Device d = oltTopology.deviceService.getDevice(DEVICE_ID_1);
        Port port = new MockPort();
        DeviceEvent portAdd = deviceEvent(DeviceEvent.Type.PORT_ADDED, DEVICE_ID_1, port);
        deviceListener.event(portAdd);
        oltTopology.lldpPeriodicity(2);
        Thread.sleep(2000);
        Ethernet responsePacket = fetchPacket(1);
        assertThat(responsePacket, notNullValue());
        checkLldpPacket(responsePacket);
    }

    /**
     * Testing Device Delete Scenario with Packet Out.
     *
     */
    @Test
    public void testDeviceDeleted() {
        log.info("oltTopology {}", oltTopology);
        Device d = oltTopology.deviceService.getDevice(DEVICE_ID_1);
        Port port = new MockPort();
        DeviceEvent portAdd = deviceEvent(DeviceEvent.Type.PORT_ADDED, DEVICE_ID_1, port);
        deviceListener.event(portAdd);
        Ethernet responsePacket = fetchPacket(1);
        assertThat(responsePacket, notNullValue());
        checkLldpPacket(responsePacket);
        DeviceEvent portRem = deviceEvent(DeviceEvent.Type.DEVICE_REMOVED, DEVICE_ID_1, port);
        deviceListener.event(portRem);
    }

    /**
     * Testing Port Delete Scenario After Packet Handle for Packet in.
     *
     */
    @Test
    public void testPortDelAfterHandlePacket() {
        Device d = oltTopology.deviceService.getDevice(DEVICE_ID_1);
        Port port = new MockPort();
        DeviceEvent portAdd = deviceEvent(DeviceEvent.Type.PORT_ADDED, DEVICE_ID_1, port);
        deviceListener.event(portAdd);
        MacAddress destMac = MacAddress.valueOf(OsgiPropertyConstants.DEFAULT_DEST_MAC_ADDRESS_DEFAULT);
        MacAddress srcMac = MacAddress.valueOf("c6:b1:cd:40:dc:93");
        String serialNumber = "switch-1";
        final short ttlInSec = 120;
        final short chasisId = 0;
        String portName = "p0";
        Ip4Address devIpAddr = Ip4Address.valueOf("192.168.1.1");
        Ethernet packet = createLldpPacket(destMac, srcMac, chasisId, portName,
                ttlInSec, serialNumber, devIpAddr.toString());

        ConnectPoint cp = new ConnectPoint(d.id(), port.number());
        sendInboundPacket(packet, cp);
        // Need to have a delay before the validation as the packet processing now happens in a different thread
        assertAfter(ASSERTION_DELAY, ASSERTION_LENGTH, () -> {
            validateNeighborList(oltTopology.getNeighbours());
        });
        DeviceEvent portRem = deviceEvent(DeviceEvent.Type.PORT_REMOVED, DEVICE_ID_1, port);
        deviceListener.event(portRem);
        assertAfter(ASSERTION_DELAY, ASSERTION_LENGTH, () -> {
            assertThat(oltTopology.getNeighbours().size(), is(0));
        });
    }

    /**
     * Testing Device Delete Scenario After Packet Handle for Packet in.
     *
     */
    @Test
    public void testDeviceDelAfterHandlePacket() {
        Device d = oltTopology.deviceService.getDevice(DEVICE_ID_1);
        Port port = new MockPort();
        DeviceEvent portAdd = deviceEvent(DeviceEvent.Type.PORT_ADDED, DEVICE_ID_1, port);
        deviceListener.event(portAdd);
        MacAddress destMac = MacAddress.valueOf(OsgiPropertyConstants.DEFAULT_DEST_MAC_ADDRESS_DEFAULT);
        MacAddress srcMac = MacAddress.valueOf("c6:b1:cd:40:dc:93");
        String serialNumber = "switch-1";
        final short ttlInSec = 120;
        final short chasisId = 0;
        String portName = "p0";
        Ip4Address devIpAddr = Ip4Address.valueOf("192.168.1.1");
        Ethernet packet = createLldpPacket(destMac, srcMac, chasisId, portName,
                ttlInSec, serialNumber, devIpAddr.toString());

        ConnectPoint cp = new ConnectPoint(d.id(), port.number());
        sendInboundPacket(packet, cp);
        assertAfter(ASSERTION_DELAY, ASSERTION_LENGTH, () -> {
            validateNeighborList(oltTopology.getNeighbours());
            assertThat(oltTopology.getNeighbours().size(), is(1));
        });
        DeviceEvent portRem = deviceEvent(DeviceEvent.Type.DEVICE_REMOVED, DEVICE_ID_1, port);
        deviceListener.event(portRem);
        assertAfter(ASSERTION_DELAY, ASSERTION_LENGTH, () -> {
            assertThat(oltTopology.getNeighbours().size(), is(0));
        });
    }

    /**
     * Creates dummy packet for LLDP packet to test Packet in scenario.
     *
     * @param destMac    Destination Mac address of LLDP packet
     * @param srcMac     Source mac address of LLDP packet
     * @param chassisId  Chassis ID tlv value
     * @param port       port Id tlv value
     * @param ttl        TTL tlv value
     * @param systemName System name tlv value
     * @param mgmtAddr   Management Address tlv value
     * @return LLDP ethernet packet
     */
    private Ethernet createLldpPacket(MacAddress destMac, MacAddress srcMac,
                                      int chassisId, String port, short ttl,
                                      String systemName, String mgmtAddr) {
        Ethernet ethPkt = new Ethernet();
        ethPkt.setEtherType(Ethernet.TYPE_LLDP);
        ethPkt.setDestinationMACAddress(destMac);
        ethPkt.setSourceMACAddress(srcMac);

        LLDP lldpPkt = new LLDP();

        setChassisId(lldpPkt, chassisId);
        setPortId(lldpPkt, port);
        setTtl(lldpPkt, ttl);

        List<LLDPTLV> optionalTlv = new ArrayList<>();
        optionalTlv.add(createSystemNameTlv(systemName));
        optionalTlv.add(createMgmtAddressTlv(mgmtAddr));

        lldpPkt.setOptionalTLVList(optionalTlv);

        ethPkt.setPayload(lldpPkt);
        return ethPkt;
    }

    /**
     * Sets Chassis ID TLV for LLDP packet.
     *
     * @param lldpPkt   LLDP packet reference
     * @param chassisId Chassid ID tlv value
     */
    private void setChassisId(LLDP lldpPkt, final int chassisId) {
        final byte chassisTlvSubtype = 1;

        byte[] chassis = ArrayUtils.addAll(new byte[]{chassisTlvSubtype},
                ByteBuffer.allocate(String.valueOf(chassisId).length())
                        .put(String.valueOf(chassisId).getBytes()).array());

        LLDPTLV chassisTlv = new LLDPTLV();
        lldpPkt.setChassisId(chassisTlv.setLength((byte) chassis.length)
                .setType(LLDP.CHASSIS_TLV_TYPE)
                .setValue(chassis));
    }

    /**
     * Sets Port ID tlv for LLDP packet.
     *
     * @param lldpPkt   LLDP packet reference
     * @param ifaceName Port Name TLV value
     */
    public void setPortId(LLDP lldpPkt, final String ifaceName) {
        final byte portTlvSubtype = 5;

        byte[] port = ArrayUtils.addAll(new byte[]{portTlvSubtype},
                ifaceName.getBytes());

        LLDPTLV portTlv = new LLDPTLV();
        lldpPkt.setPortId(portTlv.setLength((byte) port.length)
                .setType(LLDP.PORT_TLV_TYPE)
                .setValue(port));
    }

    /**
     * Sets  TTL tlv for LLDP packet.
     *
     * @param lldpPkt    LLDP Packet reference
     * @param timeInSecs TTL tlv value in sec
     */
    public void setTtl(LLDP lldpPkt, final short timeInSecs) {
        byte[] time = ByteBuffer.allocate(2).putShort(timeInSecs).array();
        LLDPTLV ttlTlv = new LLDPTLV();
        lldpPkt.setTtl(ttlTlv.setType(LLDP.TTL_TLV_TYPE)
                .setLength((short) time.length)
                .setValue(time));
    }

    /**
     * Sets System name tlv for LLDP packet.
     *
     * @param systemName System name tlv value
     * @return systemName tlv
     */
    public LLDPTLV createSystemNameTlv(String systemName) {
        byte[] bytes = systemName.getBytes();
        LLDPTLV sysNameTlv = new LLDPTLV();
        return sysNameTlv.setType(SYSTEMNAME_TLV_TYPE)
                .setLength((byte) bytes.length)
                .setValue(bytes);
    }

    /**
     * Sets Management address tlv for LLDP packet.
     *
     * @param mgmtAddress Management address tlv value
     * @return Management address tlv
     */
    public LLDPTLV createMgmtAddressTlv(String mgmtAddress) {
        final byte mgmtAddressTlvType = 0x8;
        final byte ipAddressSubType = 0x1; // IPv4
        // 5 below is address subtype + IP4 address len
        final byte ipAddrStrLen = 0x5;
        final byte interfaceSubtype = 0x1;
        final int interfaceNum = 0;
        final byte oidString = 0x0;
        Ip4Address ipAddr = Ip4Address.valueOf(mgmtAddress);

        byte[] addrStr = ArrayUtils.addAll(new byte[]{ipAddressSubType},
                ipAddr.toOctets());

        byte[] ipAddrBytes = ArrayUtils.addAll(new byte[]{ipAddrStrLen},
                addrStr);
        byte[] bytesInterfacetype = ArrayUtils.addAll(ipAddrBytes,
                ByteBuffer.allocate(1).put(interfaceSubtype).array());
        byte[] bytesInterfaceNumber = ArrayUtils.addAll(bytesInterfacetype,
                ByteBuffer.allocate(4).putInt(interfaceNum).array());
        byte[] finalMgmtAddrBytes = ArrayUtils.addAll(bytesInterfaceNumber,
                ByteBuffer.allocate(1).put(oidString).array());

        LLDPTLV mgmtAddrTlv = new LLDPTLV();
        return mgmtAddrTlv.setType(mgmtAddressTlvType)
                .setLength((byte) finalMgmtAddrBytes.length)
                .setValue(finalMgmtAddrBytes);
    }

    /*
    Mocks application id.
     */
    private static final class MockApplicationId implements ApplicationId {

        private final short id;
        private final String name;

        public MockApplicationId(short id, String name) {
            this.id = id;
            this.name = name;
        }

        @Override
        public short id() {
            return id;
        }

        @Override
        public String name() {
            return name;
        }
    }

    /*
    Mocks Core service adapter.
     */
    private static final class MockCoreService extends CoreServiceAdapter {

        private List<ApplicationId> idList = new ArrayList<>();
        private Map<String, ApplicationId> idMap = new HashMap<>();

        /*
         * (non-Javadoc)
         *
         * @see
         * org.onosproject.core.CoreServiceAdapter#getAppId(java.lang.Short)
         */
        @Override
        public ApplicationId getAppId(Short id) {
            if (id >= idList.size()) {
                return null;
            }
            return idList.get(id);
        }

        /*
         * (non-Javadoc)
         *
         * @see
         * org.onosproject.core.CoreServiceAdapter#getAppId(java.lang.String)
         */
        @Override
        public ApplicationId getAppId(String name) {
            return idMap.get(name);
        }

        /*
         * (non-Javadoc)
         *
         * @see
         * org.onosproject.core.CoreServiceAdapter#registerApplication(java.lang
         * .String)
         */
        @Override
        public ApplicationId registerApplication(String name) {
            ApplicationId appId = idMap.get(name);
            if (appId == null) {
                appId = new MockApplicationId((short) idList.size(), name);
                idList.add(appId);
                idMap.put(name, appId);
            }
            return appId;
        }

    }

    private static class MockMastershipService extends MastershipServiceAdapter {
        @Override
        public boolean isLocalMaster(DeviceId d) {
            return true;
        }
    }

    private static class MockDevice extends DefaultDevice {

        /*
        Mocks OLT device.
         */
        public MockDevice(ProviderId providerId, DeviceId id, Type type,
                          String manufacturer, String hwVersion, String swVersion,
                          String serialNumber, ChassisId chassisId, Annotations... annotations) {
            super(providerId, id, type, manufacturer, hwVersion, swVersion, serialNumber,
                    chassisId, annotations);
        }
    }

    private static class MockSadisService implements SadisService {

        @Override
        public MockSubService getSubscriberInfoService() {
            return new MockSubService();
        }

        @Override
        public MockSubService getBandwidthProfileService() {
            return new MockSubService();
        }

    }

    /*
     Mocks SubscriberAndDeviceInformationService(SADIS) information.
      */
    private static class MockSubService implements BaseInformationService {
        MockSubscriberAndDeviceInformation device =
                new MockSubscriberAndDeviceInformation(OLT_DEV_ID, VlanId.NONE, VlanId.NONE, null, null,
                        OLT_MAC_ADDRESS, Ip4Address.valueOf("10.10.10.10"));
        MockSubscriberAndDeviceInformation sub =
                new MockSubscriberAndDeviceInformation(CLIENT_NAS_PORT_ID, CLIENT_C_TAG,
                        CLIENT_S_TAG, CLIENT_NAS_PORT_ID, CLIENT_CIRCUIT_ID, null, null);

        @Override
        public SubscriberAndDeviceInformation get(String id) {
            if (id.equals(OLT_DEV_ID)) {
                return device;
            } else {
                return sub;
            }
        }

        @Override
        public void clearLocalData() {

        }

        @Override
        public void invalidateAll() {
        }

        public void invalidateId(String id) {
        }

        public SubscriberAndDeviceInformation getfromCache(String id) {
            return null;
        }
    }

    /*
    Mocks SubscriberAndDeviceInformation.
     */
    private static class MockSubscriberAndDeviceInformation extends SubscriberAndDeviceInformation {

        MockSubscriberAndDeviceInformation(String id, VlanId ctag,
                                           VlanId stag, String nasPortId,
                                           String circuitId, MacAddress hardId,
                                           Ip4Address ipAddress) {
            UniTagInformation uniTagInformation = new UniTagInformation.Builder()
                    .setPonCTag(ctag)
                    .setPonSTag(stag)
                    .build();
            List<UniTagInformation> uniTagInformationList = Lists.newArrayList(uniTagInformation);
            this.setUniTagList(uniTagInformationList);
            // this.setCTag(ctag);
            this.setHardwareIdentifier(hardId);
            this.setId(id);
            this.setIPAddress(ipAddress);
//            this.setSTag(stag);
            this.setNasPortId(nasPortId);
            this.setCircuitId(circuitId);
        }
    }

    private static class MockPort implements Port {

        @Override
        public boolean isEnabled() {
            return true;
        }

        public long portSpeed() {
            return 1000;
        }

        public Element element() {
            return null;
        }

        public PortNumber number() {
            return PortNumber.portNumber(1);
        }

        public Annotations annotations() {
            return new MockAnnotations();
        }

        public Type type() {
            return Port.Type.FIBER;
        }

        private static class MockAnnotations implements Annotations {

            @Override
            public String value(String val) {
                return "nni-";
            }

            public Set<String> keys() {
                return Sets.newHashSet("portName");
            }
        }
    }

    /*
    Mocks Device Service Adapter.
     */
    private class MockDeviceService extends DeviceServiceAdapter {

        private ProviderId providerId = new ProviderId("of", "foo");
        private final Device device1 = new MockDevice(providerId, DEVICE_ID_1, Device.Type.SWITCH,
                "foo.inc", "0", "0", OLT_DEV_ID, new ChassisId(),
                DEVICE_ANNOTATIONS);

        @Override
        public Device getDevice(DeviceId devId) {
            return device1;

        }

        @Override
        public Iterable<Device> getDevices() {
            List<Device> devices = new ArrayList<>();
            devices.add(device1);
            return devices;
        }

        @Override
        public Port getPort(ConnectPoint cp) {
            return new MockPort();
        }

        @Override
        public Port getPort(DeviceId deviceId, PortNumber portNumber) {
            return new MockPort();
        }

        @Override
        public List<Port> getPorts(DeviceId deviceId) {
            return Lists.newArrayList(new MockPort());
        }

        @Override
        public boolean isAvailable(DeviceId d) {
            return true;
        }

        @Override
        public void addListener(DeviceListener listener) {
            deviceListener = listener;
        }

        @Override
        public void removeListener(DeviceListener listener) {

        }
    }
}
