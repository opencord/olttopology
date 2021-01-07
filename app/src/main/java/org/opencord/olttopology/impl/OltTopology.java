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

import static java.util.concurrent.Executors.newSingleThreadExecutor;
import static org.onlab.util.Tools.groupedThreads;

import org.apache.commons.lang.ArrayUtils;
import org.onlab.packet.EthType;
import org.onlab.packet.Ethernet;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.LLDP;
import org.onlab.packet.LLDPTLV;
import org.onlab.packet.MacAddress;
import org.onlab.util.KryoNamespace;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.codec.CodecService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Port;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.store.serializers.KryoNamespaces;
import org.onosproject.store.service.EventuallyConsistentMap;
import org.onosproject.store.service.StorageService;
import org.onosproject.store.service.WallClockTimestamp;
import org.opencord.olttopology.OltNeighborInfo;
import org.opencord.olttopology.OltTopologyInformationService;
import org.opencord.sadis.BaseInformationService;
import org.opencord.sadis.SadisService;
import org.opencord.sadis.SubscriberAndDeviceInformation;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Dictionary;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ExecutorService;
import java.util.stream.Collectors;

import static org.onlab.util.Tools.get;
import static org.opencord.olttopology.impl.OsgiPropertyConstants.DEFAULT_CHASSIS_ID;
import static org.opencord.olttopology.impl.OsgiPropertyConstants.DEFAULT_CHASSIS_ID_DEFAULT;
import static org.opencord.olttopology.impl.OsgiPropertyConstants.DEFAULT_DEST_MAC_ADDRESS;
import static org.opencord.olttopology.impl.OsgiPropertyConstants.DEFAULT_DEST_MAC_ADDRESS_DEFAULT;
import static org.opencord.olttopology.impl.OsgiPropertyConstants.DEFAULT_TTL_IN_SECS;
import static org.opencord.olttopology.impl.OsgiPropertyConstants.DEFAULT_TTL_IN_SECS_DEFAULT;
import static org.opencord.olttopology.impl.OsgiPropertyConstants.DEFAULT_LLDP_SEND_PERIODICITY;
import static org.opencord.olttopology.impl.OsgiPropertyConstants.LLDP_SEND_PERIODICITY_STR;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Application to keep track of the topology of OLT devices.
 */
@Component(immediate = true,
        property = {
                DEFAULT_DEST_MAC_ADDRESS + ":String=" + DEFAULT_DEST_MAC_ADDRESS_DEFAULT,
                DEFAULT_TTL_IN_SECS + ":Integer=" + DEFAULT_TTL_IN_SECS_DEFAULT,
                DEFAULT_CHASSIS_ID + ":Integer=" + DEFAULT_CHASSIS_ID_DEFAULT,
                LLDP_SEND_PERIODICITY_STR + ":Integer=" + DEFAULT_LLDP_SEND_PERIODICITY
        }
)
public class OltTopology implements OltTopologyInformationService {
    // Subtype value for IPv4 as per the LLDP specs
    public static final byte IP_ADDR_SUB_TYPE = 0x1;
    // 5 below is address subtype + IP4 address len
    public static final byte IP_ADDR_STRING_LEN = 0x5;
    // Value of interface sub type as per the LLDP specs
    public static final byte INTERFACE_SUB_TYPE = 0x1;
    // Value of interface number set in the management address
    // field of LLDP packets being sent out
    public static final int INTERFACE_NUM = 0;
    // Value of the OID set in the management address field of
    // LLDP packets being sent out
    public static final byte OID_STRING = 0x0;
    // Value of SystemName TLV as per the LLDP specs
    public static final byte SYSTEMNAME_TLV_TYPE = 0x5;
    // Value of Management Address TLV as per the LLDP specs
    public static final byte MANAGEMENT_ADDR_TLV_TYPE = 0x8;
    // Value of Port TLV sub type as per the LLDP specs
    public static final byte PORT_TLV_SUB_TYPE = 5;
    private static final String APP_NAME = "org.opencord.olttopology";
    // Name for the consistent map where the neighbor information is stored
    private static final String NEIGHBORS = "olt-neighbors";
    private final Logger log = getLogger(getClass());
    // deviceListener to be able to receive events about the OLT devices
    private final DeviceListener deviceListener = new InternalDeviceListener();
    // Service to execute periodic sending of LLDP packets
    private final ScheduledExecutorService scheduledExecutorService =
            Executors.newSingleThreadScheduledExecutor();
    // our application-specific event handler for processing LLDP messages
    // received from the OLT devices
    private final ReactivePacketProcessor processor = new ReactivePacketProcessor();
    // Map for storing information about the OLTs, is map of OLT deviceId to
    // uplink port of the OLT
    private final Map<DeviceId, Port> oltPortMap = new ConcurrentHashMap<>();
    // cfg variable to set the parameters dynamically.
    protected String destMacAddress = DEFAULT_DEST_MAC_ADDRESS_DEFAULT;
    // References to the various services that this app uses
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected MastershipService mastershipService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService componentConfigService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected StorageService storageService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CodecService codecService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected SadisService sadisService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;
    protected BaseInformationService<SubscriberAndDeviceInformation> subsService;
    private short ttlInSecs = DEFAULT_TTL_IN_SECS_DEFAULT;
    private int chassisId = DEFAULT_CHASSIS_ID_DEFAULT;
    private int lldpSendPeriodicity = DEFAULT_LLDP_SEND_PERIODICITY;
    private ApplicationId appId;
    // Map for storing information about the neighbor connected to an OLT port
    private EventuallyConsistentMap<ConnectPoint, OltNeighborInfo> neighbors;
    private ScheduledFuture<?> futureTask;

    protected ExecutorService packetProcessorExecutor;
    protected ExecutorService eventExecutor;

    private static boolean isNniPort(Port port) {
        if (port.annotations().keys().contains("portName")) {
            return port.annotations().value("portName").contains("nni-");
        }
        return false;
    }

    @Activate
    public void activate(ComponentContext context) {
        modified(context);
        appId = coreService.registerApplication(APP_NAME);
        componentConfigService.registerProperties(getClass());
        codecService.registerCodec(OltNeighborInfo.class, new OltTopologyInformationCodec());

        subsService = sadisService.getSubscriberInfoService();

        // look for all provisioned devices in Sadis and put them in oltData
        deviceService.getDevices().forEach(this::createAndProcessDevice);

        // The NEIGHBORS map should be available across ONOS instance failures,
        // create it using the storage service.
        KryoNamespace serializer = KryoNamespace.newBuilder()
                .register(KryoNamespaces.API)
                .register(OltNeighborInfo.class)
                .register(ConnectPoint.class)
                .register(java.util.Date.class)
                .register(org.onosproject.net.Port.class)
                .register(org.onlab.packet.LLDPOrganizationalTLV.class)
                .build();

        neighbors = storageService.<ConnectPoint, OltNeighborInfo>eventuallyConsistentMapBuilder()
                .withName(NEIGHBORS)
                .withSerializer(serializer)
                .withTimestampProvider((k, v) -> new WallClockTimestamp())
                .build();

        deviceService.addListener(deviceListener);

        // register our event handler
        packetService.addProcessor(processor, PacketProcessor.director(2));
        futureTask = scheduledExecutorService.scheduleAtFixedRate(this::oltTopologyTimerTask, 0, lldpSendPeriodicity,
                TimeUnit.MINUTES);
        packetProcessorExecutor = newSingleThreadExecutor(groupedThreads("onos/olttopology", "packet-%d", log));
        eventExecutor = newSingleThreadExecutor(groupedThreads("onos/olttopology", "events-%d", log));

        log.info("Started with Application ID {}", appId.id());
    }

    @Deactivate
    public void deactivate() {
        futureTask.cancel(true);
        scheduledExecutorService.shutdownNow();
        packetService.removeProcessor(processor);
        deviceService.removeListener(deviceListener);
        codecService.unregisterCodec(OltNeighborInfo.class);
        componentConfigService.unregisterProperties(getClass(), false);
        packetProcessorExecutor.shutdown();
        eventExecutor.shutdown();
        log.info("Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();
        try {
            String destMac = get(properties, DEFAULT_DEST_MAC_ADDRESS);
            destMacAddress = Objects.isNull(destMac) ? DEFAULT_DEST_MAC_ADDRESS_DEFAULT : destMac;
            String ttlInsecsStr = get(properties, DEFAULT_TTL_IN_SECS);
            ttlInSecs = Short.parseShort(ttlInsecsStr.trim());

            String chassisIdStr = get(properties, DEFAULT_CHASSIS_ID);
            chassisId = Integer.parseInt(chassisIdStr.trim());

            String lldpPeriodicity = get(properties, LLDP_SEND_PERIODICITY_STR);
            int newLldpSendPeriodicity = Integer.parseInt(lldpPeriodicity);

            if (newLldpSendPeriodicity <= 0) {
                log.error("lldpSendPeriodicity should be a positive integer");
            } else if (newLldpSendPeriodicity != lldpSendPeriodicity) {
                lldpSendPeriodicity = newLldpSendPeriodicity;
                lldpPeriodicity(newLldpSendPeriodicity);
            }

            log.debug("OLT properties: destMacAddress: {}, ttlInSecs: {}, chassisId: {}, lldpSendPeriodicity{}",
                    destMacAddress, ttlInSecs, chassisId, lldpSendPeriodicity);
        } catch (Exception e) {
            log.error("Error while modifying the properties", e);
        }
    }

    @Override
    public Map<ConnectPoint, OltNeighborInfo> getNeighbours() {
        return neighbors.entrySet().stream().collect(Collectors.toMap(Entry::getKey, Entry::getValue));
    }

    /**
     * Sets periodicity in minutes for sending out LLDP packet to OLT NNI Ports.
     *
     * @param timer Value in minutes.
     */
    @Override
    public void lldpPeriodicity(int timer) {
        if (timer > 0) {
            if (futureTask != null) {
                futureTask.cancel(true);
            }

            futureTask = scheduledExecutorService.scheduleAtFixedRate(this::oltTopologyTimerTask, 0,
                    timer,
                    TimeUnit.MINUTES);
            log.info("LLDP Packet out Periodicity updated to {} minutes", timer);
        }
    }

    /**
     * Creates entry in the oltData map.
     * provision LLDP flow on enabled NNI ports if device is present in Sadis config
     *
     * @param dev Device to look for
     */
    private void createAndProcessDevice(Device dev) {
        SubscriberAndDeviceInformation deviceInfo = subsService.get(dev.serialNumber());
        log.debug("CreateAndProcessDevice: deviceInfo {}", deviceInfo);

        if (deviceInfo != null) {
            // TODO FIXME, this works only with one NNI
            Optional<Port> optPort = deviceService.getPorts(dev.id())
                    .stream().filter(OltTopology::isNniPort).findFirst();
            if (optPort.isPresent()) {
                Port port = optPort.get();
                oltPortMap.put(dev.id(), port);
                return;
            }
        }
        log.warn("CreateAndProcessDevice: failed to update the oltdata for device {}", dev);
    }

    /**
     * Updates OltData Map with new AccessDeviceData if it is already present in OltMap,
     * Provisions LLDP flow on enabled NNI port if it is present in Sadis config
     * Only one NNI port is supported as of now.
     *
     * @param dev    Device to look for
     * @param uplink Uplink port number
     * @return true if updated else false
     */
    private boolean updateOltData(Device dev, Port uplink) {
        // check if this device is provisioned in Sadis
        SubscriberAndDeviceInformation deviceInfo = subsService.get(dev.serialNumber());
        log.debug("updateAccessDevice: deviceInfo {}", deviceInfo);

        if (deviceInfo != null) {
            oltPortMap.replace(dev.id(), uplink);
            log.debug("updateAccessDevice: Stored did {} uplink {}", dev.id(), uplink);
            return true;
        }
        return false;
    }

    /**
     * Sends LLDP Packet to OLT NNI Port.
     *
     * @param devId   Access Device data for OLT
     * @param nniPort NNI port info of OLT
     */
    private void sendLldpPackets(DeviceId devId, Port nniPort) {
        if (!mastershipService.isLocalMaster(devId)) {
            return;
        }

        // Get NNI Port name to be filled in LLDP packet port TLV.
        String portName = (nniPort.annotations().value("portName").isEmpty()) ? "" :
                nniPort.annotations().value("portName");

        // Get System Name value from device name.
        Device d = deviceService.getDevice(devId);
        String[] systemName = d.id().uri().toString().split(":", 2);

        MacAddress destMac = MacAddress.valueOf(destMacAddress);
        MacAddress srcMac = createMacFromDevId(d.id());

        SubscriberAndDeviceInformation deviceInfo = subsService.get(d.serialNumber());

        // Initialized deviceIP address, to be sent in Management Address TLV.
        Ip4Address devIpAddr = Ip4Address.valueOf("0.0.0.0");

        // Get OLT device IP address from deviceInfo, to be filled in management address TLV.
        if (deviceInfo != null) {
            devIpAddr = deviceInfo.ipAddress();
            log.debug("sendLldpPackets: did {} nniPort {} devIP {}", d.id(), nniPort, devIpAddr);
        } else {
            log.warn("device {} not found in Sadis NOT sending LLDP packet", d.id());
            return;
        }

        //Created LLDP packet.
        Ethernet packet = createLldpPacket(destMac, srcMac, chassisId,
                portName, ttlInSecs, systemName[1], devIpAddr
                        .toString());

        // Create the connect point to send the packet to and emit
        ConnectPoint toSendTo = new ConnectPoint(d.id(), nniPort.number());

        //Sends LLDP packet to connect point(NNI port).
        TrafficTreatment t = DefaultTrafficTreatment.builder()
                .setOutput(toSendTo.port()).build();
        OutboundPacket o = new DefaultOutboundPacket(
                toSendTo.deviceId(), t,
                ByteBuffer.wrap(packet.serialize()));
        if (log.isTraceEnabled()) {
            log.trace("Sending LLDP packet {} at {}",
                    packet, toSendTo);
        }

        packetService.emit(o);
    }

    /**
     * Creates MAC address for LLDP packet from OLT device ID string.
     *
     * @param id Device ID of OLT
     * @return Mac address
     */
    private MacAddress createMacFromDevId(DeviceId id) {
        String strId = id.toString();
        String macStr = strId.substring(7);
        String formattedMac = macStr.replaceAll("(.{2})", "$1" + ":");
        formattedMac = formattedMac.substring(0, formattedMac.length() - 1);

        return MacAddress.valueOf(formattedMac);
    }

    /**
     * Creates LLDP packet to be sent out of OLT.
     *
     * @param destMac    Destination LLDP Mac address
     * @param srcMac     Source Mac of OLT device
     * @param chassisId  Chassis ID TLV value
     * @param port       NNI port information
     * @param ttl        TTL value in sec
     * @param systemName System name TLV value
     * @param mgmtAddr   Management Address TLV value
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
    private void setPortId(LLDP lldpPkt, final String ifaceName) {

        byte[] port = ArrayUtils.addAll(new byte[]{PORT_TLV_SUB_TYPE},
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
    private void setTtl(LLDP lldpPkt, final short timeInSecs) {
        byte[] time = ByteBuffer.allocate(2).putShort(timeInSecs).array();

        LLDPTLV ttlTlv = new LLDPTLV();

        lldpPkt.setTtl(ttlTlv.setType(LLDP.TTL_TLV_TYPE)
                .setLength((short) time.length)
                .setValue(time));
    }

    /**
     * Creates System name TLV for LLDP packet.
     *
     * @param systemName System name tlv value
     * @return systemName TLV
     */
    private LLDPTLV createSystemNameTlv(String systemName) {
        byte[] bytes = systemName.getBytes();

        LLDPTLV sysNameTlv = new LLDPTLV();

        return sysNameTlv.setType(SYSTEMNAME_TLV_TYPE)
                .setLength((byte) bytes.length)
                .setValue(bytes);
    }

    /**
     * Sets Management address TLV for LLDP packet.
     *
     * @param mgmtAddress Management address tlv value
     * @return Management address TLV
     */
    private LLDPTLV createMgmtAddressTlv(String mgmtAddress) {

        Ip4Address ipAddr = Ip4Address.valueOf(mgmtAddress);

        byte[] addrStr = ArrayUtils.addAll(new byte[]{IP_ADDR_SUB_TYPE},
                ipAddr.toOctets());

        byte[] ipAddrBytes = ArrayUtils.addAll(new byte[]{IP_ADDR_STRING_LEN},
                addrStr);

        byte[] bytesInterfacetype = ArrayUtils.addAll(ipAddrBytes,
                ByteBuffer.allocate(1).put(INTERFACE_SUB_TYPE).array());
        byte[] bytesInterfaceNumber = ArrayUtils.addAll(bytesInterfacetype,
                ByteBuffer.allocate(4).putInt(INTERFACE_NUM).array());
        byte[] finalMgmtAddrBytes = ArrayUtils.addAll(bytesInterfaceNumber,
                ByteBuffer.allocate(1).put(OID_STRING).array());

        LLDPTLV mgmtAddrTlv = new LLDPTLV();
        return mgmtAddrTlv.setType(MANAGEMENT_ADDR_TLV_TYPE)
                .setLength((byte) finalMgmtAddrBytes.length)
                .setValue(finalMgmtAddrBytes);
    }

    /**
     * Processes incoming LLDP packets from NNI ports.
     *
     * @param pkt Inbound packet received at ONOS from OLT NNI port
     */
    private void handleLldpPacket(InboundPacket pkt) {

        Ethernet packet = pkt.parsed();

        if (packet == null) {
            log.warn("Packet is null");
            return;
        }

        log.debug("Got a packet {}", packet);

        // Check if Ethernet type is LLDP.
        if (packet.getEtherType() == Ethernet.TYPE_LLDP) {
            // Get payload of Packet.
            LLDP lldpPacket = (LLDP) packet.getPayload();

            // Fetch all optional TLVs from Packet.
            List<LLDPTLV> optionalTLVs = lldpPacket.getOptionalTLVList();

            // Look for the system name and neighbor
            // management IP address TLVs.
            String systemName = null;
            String neighMgmtAddr = "";
            if (optionalTLVs != null) {
                for (LLDPTLV tlv : optionalTLVs) {
                    // Fetching system name TLV.
                    if (tlv.getType() == SYSTEMNAME_TLV_TYPE) {
                        systemName = new String(tlv.getValue());
                    } else if (tlv.getType() == MANAGEMENT_ADDR_TLV_TYPE) {
                        /* Fetching 4 Octets from MANAGEMENT Address TLV to get IP address. */
                        byte[] neighMgmtIpBytes = Arrays.copyOfRange(tlv.getValue(), 2, 6);
                        Ip4Address neighMgmtIpaddress = Ip4Address.valueOf(neighMgmtIpBytes);
                        neighMgmtAddr = neighMgmtIpaddress.toString();
                    }
                }
            }

            if (systemName == null) {
                // We expect the system name to be sent by the neighbor, in absence
                // we don't store the information
                return;
            }

            int portIdTlvLen = lldpPacket.getPortId().getLength();

            String portName = new String(lldpPacket.getPortId().getValue())
                    .substring(1, portIdTlvLen);

            // The OLT name stored in the topology information is the device uri
            // excluding the "of:" part
            DeviceId devId = pkt.receivedFrom().deviceId();
            String deviceUri = devId.uri().toString();
            String[] oltName = deviceUri.split(":", 2);
            Port oltNni = deviceService.getPort(pkt.receivedFrom());

            String devSerial = deviceService.getDevice(devId).serialNumber();

            // Creating object of OltNeighborInfo with all info required.
            OltNeighborInfo newNeighbor = new OltNeighborInfo(systemName,
                    portName,
                    oltName[1],
                    oltNni,
                    devSerial);
            newNeighbor.setMgmtAddress(neighMgmtAddr);

            // Store all the other optional in the neighbour information
            // this is for future use
            for (LLDPTLV tlv : optionalTLVs) {
                if (tlv.getType() != SYSTEMNAME_TLV_TYPE && tlv.getType() != MANAGEMENT_ADDR_TLV_TYPE) {
                    newNeighbor.addOtherOptionalLldpTlvs(tlv);
                }
            }

            /*
            Checking if Neighbor information is already present.
            If Yes, then update current information, else
            adding new information.
             */
            OltNeighborInfo curNeighbor = neighbors.get(pkt.receivedFrom());
            if (newNeighbor.equals(curNeighbor)) {
                curNeighbor.updateTimeStamp();
                neighbors.put(pkt.receivedFrom(), curNeighbor);
            } else {
                // received first time on this connect point or old was purged
                neighbors.put(pkt.receivedFrom(), newNeighbor);
            }
        }
    }

    /**
     * Removes Entry for device from Olt topology table.
     *
     * @param devIdToRm Device ID to be removed
     */
    void removeNeighborsOfDevice(DeviceId devIdToRm) {
        for (Map.Entry<ConnectPoint, OltNeighborInfo> neighEntry : neighbors.entrySet()) {
            if (neighEntry.getKey().deviceId().toString().contains(devIdToRm.toString())) {
                neighbors.remove(neighEntry.getKey());
            }
        }
    }

    /**
     * oltTopologyTimerTask method to send LLDP packets periodically to the neighbours.
     */
    public void oltTopologyTimerTask() {
        oltPortMap.forEach((key, p) -> {
            //Port p = deviceService.getPort(key, value);
            if (p != null  && p.isEnabled()) {
                sendLldpPackets(key, p);
            }
        });
    }

    private class InternalDeviceListener implements DeviceListener {
        /**
         * Device Listener Event, will be called if Device is added or state is changed or Updated.
         *
         * @param event Device event
         */
        @Override
        public void event(DeviceEvent event) {
            eventExecutor.execute(() -> {
                DeviceId devId = event.subject().id();
                /* Checking DEVICE_REMOVED and DEVICE_AVAILABILITY_CHANGED events before
                Mastership check as with these events mastership check will always give false.
                */
                if (event.type().equals(DeviceEvent.Type.DEVICE_REMOVED)) {
                    removeNeighborsOfDevice(devId);
                    return;
                } else if (event.type().equals(DeviceEvent.Type.DEVICE_AVAILABILITY_CHANGED)) {
                    if (!deviceService.isAvailable(devId)) {
                        removeNeighborsOfDevice(devId);
                        return;
                    }
                }

                if (!mastershipService.isLocalMaster(devId)) {
                    return;
                }

                switch (event.type()) {
                    case DEVICE_ADDED:
                        if (!oltPortMap.containsKey(devId)) {
                            createAndProcessDevice(deviceService.getDevice(devId));
                        }
                        break;
                    case PORT_ADDED:
                    /*
                    If NNI port is detected, update it in the map.
                     */
                        /* TODO: put null check for the annotations return*/
                        if (isNniPort(event.port())) {
                            if (oltPortMap.containsKey(devId)) {
                                if (!updateOltData(deviceService.getDevice(devId), event.port())) {
                                    return;
                                }
                            } else {
                                return;
                            }
                        }

                        if (Objects.nonNull(oltPortMap.get(devId)) &&
                                oltPortMap.get(devId).equals(event.port()) &&
                                event.port().isEnabled()) {
                            sendLldpPackets(devId, event.port());
                        }
                        break;
                    case PORT_REMOVED:
                        // Remove from neighbor map and LLDP flow if NNI port is removed.
                        if (Objects.nonNull(oltPortMap.get(devId)) &&
                                oltPortMap.get(devId).equals(event.port())) {
                            // the uplink port has been removed; remove the connect
                            // point from the neighbors
                            neighbors.remove(new ConnectPoint(devId, event.port().number()));
                        }
                        break;
                    case PORT_UPDATED:
                        // if Port is enabled, provision LLDP flow and send LLDP packet to NNI Port.
                        if (!oltPortMap.get(devId).equals(event.port())) {
                            break;
                        }
                        if (event.port().isEnabled()) {
                            sendLldpPackets(devId, event.port());
                        } else {
                            neighbors.remove(new ConnectPoint(devId, event.port().number()));
                        }
                        break;

                    default:
                        log.debug("event {} not handle for the device {}", event.type(), devId);
                        break;
                }
            });
        }
    }

    /*
     * Class to do the processing of the LLDP packets received from the Packet Service.
     */
    private class ReactivePacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            packetProcessorExecutor.execute(() -> {
                DeviceId devId = context.inPacket().receivedFrom().deviceId();
                if (!mastershipService.isLocalMaster(devId)) {
                    return;
                }
                // Extract the original Ethernet frame from the packet information
                InboundPacket pkt = context.inPacket();
                Ethernet ethPkt = pkt.parsed();

                if (ethPkt == null) {
                    log.warn("ethPkt null while processing context: {}", context);
                    return;
                }

                if (EthType.EtherType.lookup(ethPkt.getEtherType()) == EthType.EtherType.LLDP) {
                    handleLldpPacket(context.inPacket());
                }
            });
        }
    }
}