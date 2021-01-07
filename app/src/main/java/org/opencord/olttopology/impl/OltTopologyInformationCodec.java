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
package org.opencord.olttopology.impl;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.onlab.packet.LLDPTLV;
import org.onosproject.codec.CodecContext;
import org.onosproject.codec.JsonCodec;
import org.opencord.olttopology.OltNeighborInfo;

import java.util.Date;
import java.util.List;

/*
Codec for JSON encoding of OLT topology information.
 */
public class OltTopologyInformationCodec extends JsonCodec<OltNeighborInfo> {
    /**
     * Encoder for the information in Json format.
     *
     * @param en      : The topology information to be encoded
     * @param context : The context to which the Json data needs to be added
     * @return Json Object Node
     */
    @Override
    public ObjectNode encode(OltNeighborInfo en, CodecContext context) {
        final ObjectNode result = context.mapper().createObjectNode()
                .put("oltName", (en.oltName() == null) ? "" : en.oltName())
                .put("oltPort", (en.oltPort().annotations().value("portName").isEmpty()) ? "" :
                        en.oltPort().annotations().value("portName"))
                .put("oltSerialNo", (en.oltSerialNo() == null) ? "" : en.oltSerialNo())
                .put("neighborName", (en.neighborName() == null) ? "" : en.neighborName())
                .put("neighborPort", (en.neighborPort() == null) ? "" : en.neighborPort())
                .put("neighborManagementAddress", (en.mgmtAddr() == null) ? "" : en.mgmtAddr());

        if (en.getOtherOptionalTlvs() != null) {
            ArrayNode optionalTlvNodes = result.putArray("optionalTlvs");

            List<LLDPTLV> optionalTlvsList = en.getOtherOptionalTlvs();
            for (LLDPTLV tlv : optionalTlvsList) {
                ObjectNode optionalTlvNode = context.mapper().createObjectNode();
                optionalTlvNode.put("type", tlv.getType());
                optionalTlvNode.put("value", "0x" + byteArrayInHex(tlv.getValue()));
                optionalTlvNodes.add(optionalTlvNode);
            }
        }

        Date currentTime = new Date();
        long lastUpdatedValue = currentTime.getTime() - en.getLastUpdated().getTime();
        long lastUpdatedSecondsValue = lastUpdatedValue / 1000;
        result.put("last_updated", Long.toString(lastUpdatedSecondsValue));
        return result;
    }

    /**
     * Utility function to convert byte array to Hex String.
     *
     * @param bytes : The byte arrary to be converted
     * @return Hex string representation of the byte array
     */
    private String byteArrayInHex(byte[] bytes) {
        String s = "";
        for (byte b : bytes) {
            s += String.format("%02x", b);
        }
        return s;
    }
}
