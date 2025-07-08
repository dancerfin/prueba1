from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib import hub
import csv
import time
import statistics
from datetime import datetime
from ml import MachineLearningAlgo

# Configuración global
APP_TYPE = 1  # 1: ddos detection
PREVENTION = 1  # DDoS prevention activada
TEST_TYPE = 0   # 0: normal
INTERVAL = 5    # Intervalo de monitoreo en segundos
MIN_ATTACK_DURATION = 20  # Segundos mínimos para considerar ataque real
CONSECUTIVE_DETECTIONS = 3  # Número de detecciones positivas requeridas

# Estructuras globales para métricas de monitoreo
MONITOR_STATS = {
    'total_events': 0,
    'processed_events': 0,
    'start_time': time.time(),
    'last_report': time.time()
}

# ... (las demás estructuras globales se mantienen igual) ...

class DDoSML(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSML, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_ip_to_port = {}
        self.datapaths = {}
        self.mitigation = 0
        self.mlobj = None
        self.attack_status = {}
        
        if APP_TYPE == 1:
            self.mlobj = MachineLearningAlgo()
            self.logger.info("Modo de detección DDoS (ML) activado")
        else:
            self.logger.info("Modo de colección de datos activado")
        
        self.flow_thread = hub.spawn(self._flow_monitor)

    def _flow_monitor(self):
        hub.sleep(INTERVAL * 2)
        while True:
            current_time = time.time()
            # Reporte cada 30 segundos
            if current_time - MONITOR_STATS['last_report'] >= 30:
                elapsed = current_time - MONITOR_STATS['start_time']
                rate = (MONITOR_STATS['processed_events'] / max(1, MONITOR_STATS['total_events'])) * 100
                self.logger.info(
                    f"*** Monitor Rate: {rate:.2f}% | "
                    f"Processed: {MONITOR_STATS['processed_events']} | "
                    f"Total: {MONITOR_STATS['total_events']} | "
                    f"Elapsed: {elapsed:.1f}s"
                )
                MONITOR_STATS['last_report'] = current_time
                
            for dp in self.datapaths.values():
                self.request_flow_metrics(dp)
            hub.sleep(INTERVAL)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        MONITOR_STATS['total_events'] += 1
        try:
            datapath = ev.msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            dpid = datapath.id
            
            self.datapaths[dpid] = datapath
            self.mac_to_port.setdefault(dpid, {})
            self.arp_ip_to_port.setdefault(dpid, {})
            BLOCKED_PORTS.setdefault(dpid, [])
            self.attack_status.setdefault(dpid, {
                'active': False, 
                'start_time': 0,
                'positive_count': 0,
                'last_detection_time': 0
            })

            # Flujo por defecto (table-miss)
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                            ofproto.OFPCML_NO_BUFFER)]
            instructions = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )]
            self.add_flow(
                datapath=datapath,
                priority=0,
                match=match,
                instructions=instructions,
                serial_no=get_flow_number(dpid)
            )
            MONITOR_STATS['processed_events'] += 1
        except Exception as e:
            self.logger.error(f"Error en switch_features: {str(e)}")

    # ... (los demás métodos se mantienen igual, pero se deben agregar los contadores) ...

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        MONITOR_STATS['total_events'] += 1
        try:
            if ev.msg.msg_len < ev.msg.total_len:
                self.logger.debug("paquete truncado: %s de %s bytes",
                                ev.msg.msg_len, ev.msg.total_len)

            msg = ev.msg
            datapath = msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            in_port = msg.match['in_port']
            dpid = datapath.id

            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocol(ethernet.ethernet)
            
            if not eth:
                return

            if eth.ethertype == ether_types.ETH_TYPE_LLDP:
                return

            dst = eth.dst
            src = eth.src

            self.mac_to_port.setdefault(dpid, {})
            self.arp_ip_to_port.setdefault(dpid, {})
            self.arp_ip_to_port[dpid].setdefault(in_port, [])
            BLOCKED_PORTS.setdefault(dpid, [])

            self.mac_to_port[dpid][src] = in_port
            MONITOR_STATS['processed_events'] += 1
            
            # ... (resto del método original) ...

        except Exception as e:
            self.logger.error(f"Error en packet_in: {str(e)}")

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        MONITOR_STATS['total_events'] += 1
        try:
            dpid = ev.msg.datapath.id
            flows = ev.msg.body
            
            gflows.setdefault(dpid, [])
            gflows[dpid].extend(flows)

            if ev.msg.flags == 0:
                sfe = self._speed_of_flow_entries(dpid, gflows[dpid])
                ssip = self._speed_of_source_ip(dpid, gflows[dpid])
                rfip = self._ratio_of_flowpair(dpid, gflows[dpid])
                sdfp, sdfb = self._stddev_packets(dpid, gflows[dpid])

                if APP_TYPE == 1 and get_iteration(dpid) == 1:
                    self.logger.info(f"Switch {dpid} - sfe:{sfe} ssip:{ssip} rfip:{rfip} sdfp:{sdfp} sdfb:{sdfb}")
                    result = self.mlobj.classify([sfe, ssip, rfip, sdfp, sdfb])
                    
                    if '1' in result:
                        if self._is_real_attack(dpid, result):
                            self.logger.warning(f"¡Ataque DDoS confirmado en Switch {dpid}!")
                            self.mitigation = 1
                            if PREVENTION == 1:
                                self._activate_prevention(dpid)
                        else:
                            self.logger.info(f"Switch {dpid}: Señales de ataque en progreso...")
                    else:
                        self.logger.info(f"Switch {dpid}: Tráfico normal")
                        if self.mitigation == 1:
                            self._deactivate_prevention(dpid)
                            self.mitigation = 0
                        self._reset_attack_status(dpid)

            gflows[dpid] = []
            set_iteration(dpid, 1)
            MONITOR_STATS['processed_events'] += 1
            
        except Exception as e:
            self.logger.error(f"Error en flow_stats: {str(e)}")

if __name__ == '__main__':
    from ryu.cmd import manager
    manager.main()