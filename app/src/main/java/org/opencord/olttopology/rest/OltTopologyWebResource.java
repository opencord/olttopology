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
package org.opencord.olttopology.rest;
import org.onosproject.rest.AbstractWebResource;
import org.opencord.olttopology.OltNeighborInfo;
import org.opencord.olttopology.OltTopologyInformationService;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
/**
 * OltTopology Information Service web resource.
 */
@Path("oltTopologyApp")
public class OltTopologyWebResource extends AbstractWebResource {
    private final OltTopologyInformationService service = get(OltTopologyInformationService.class);
    /**
     * Shows the information about the connectivity between the
     * ports of the OLT and ports of the leaf switch.
     *
     * @return 200 OK
     */
    @GET
    @Path("show")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getOltTopology() {
        Iterable<OltNeighborInfo> neighbourInfos = service.getNeighbours().values();
        return ok(encodeArray(OltNeighborInfo.class, "entries", neighbourInfos).toString()).build();
    }
}