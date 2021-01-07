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
package org.opencord.olttopology.cli;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.net.ConnectPoint;
import org.opencord.olttopology.OltNeighborInfo;
import org.opencord.olttopology.OltTopologyInformationService;

import java.util.Map;

/**
 * OLT Topology CLI Command.
 * <p>
 * Shows the current topology in the CLI.
 */
@Service
@Command(scope = "onos", name = "olt-topology", description = "OLT Topology CLI command")
public class OltTopologyGetCommand extends AbstractShellCommand {

    private static final String FORMAT = "%s";

    private OltTopologyInformationService oltTopoSer = get(OltTopologyInformationService.class);

    @Override
    protected void doExecute() {
        oltTopoSer.getNeighbours().entrySet().forEach(this::display);
    }

    private void display(Map.Entry<ConnectPoint, OltNeighborInfo> neighbor) {
        print(FORMAT, neighbor.getValue());
    }
}