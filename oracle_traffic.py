import scapy.all as scapy
from datetime import datetime, timedelta
import netifaces as ni
import csv
from rf_analyzer import rf_analyzer
from sql_parser import sql_parser

from db_event_ui import db_event_ui


class oracle_traffic_analyzer:
    def __init__(self, iface_name, oracle_server_addr, oracle_server_port, train_mode=None):
        """
        Analyser for oracle network traffic.
        Requires scapy and netifaces

        :param iface_name: Network interface name
        :param oracle_server_addr: oracle server's IP-address(string parameter)
        :param oracle_server_port: oracle server's port
        :param train_mode: Set to list of True and what activity to record when need to collect data (e.g. [True, 'anomaly'])
        """

        if train_mode is None:
            train_mode = [False, ]
            self.__train_path = None
        self.__iface_name = iface_name
        self.__oracle_server_addr = oracle_server_addr
        self.__oracle_server_port = str(oracle_server_port)
        self.__train_mode = train_mode[0]
        self.__even_logger = db_event_ui('oracle')
        if self.__train_mode:
            self.__train_path = train_mode[1]
        self.__ids_ip = ni.ifaddresses('ens38')[ni.AF_INET][0]['addr']

        self.__packet_dict = {}
        self.__session_list_update_value = 1
        self.__query_packet_dict = {}
        self.__response_packet_dict = {}
        self.__query_index = 0
        self.__saved_index = 0
        self.__analyzed_index = 0        
        self.__fin_arr = []

    def __update_session_list(self):
        """
        Updates session list for calculating sessions' length in future
        """
        scapy_pl = scapy.PacketList(self.__packet_dict)
       
    def __sort_data_vectors(self, data_vectors):
        tuple_list = sorted(data_vectors.items(), key=lambda x: len(x[1]['sql_text']), reverse=True)
        result = {}
        for row in tuple_list:
            result[row[0]] = row[1]
        return result

    @staticmethod
    def __find_audit_row(payload, data_vectors):
        """
        Matches exact oracle audit record and network packet

        :param payload: TNS-protocol packet payload
        :param data_vectors: Set of candidates from oracle audit table
        :return: index of oracle audit record
        :rtype: str
        """
        for index, vector in data_vectors.items():
            if vector['sql_text'].encode() in payload:
                return index

        return 'not found'

    def __create_packet_info_struct(self, packet):
        """
        Creates list of useful packet information

        :param packet: TNS packet of query/response
        :return: List of packet information
        :rtype: list
        """
        payload = bytes(packet.payload.payload.payload)

        return [self.__query_index,
                datetime.now(),
                'TCP ' + str(packet[scapy.IP].src) + ':' + str(
                    packet[scapy.TCP].sport) + " > " + self.__oracle_server_addr + ":" + self.__oracle_server_port,
                payload,
                ]

    def __analyze_packet(self, packet):
        """
        Picks query and response TNS packets and forms data vectors for future ML analysis

        :param packet: Network TNS packet
        """
        payload = bytes(packet.payload.payload.payload)
        key_words_arr = [b'SELECT', b'UPDATE', b'INSERT', b'DELETE']
        _anomaly_words_arr = [b'DROP', b'TRUNCATE', b'ALTER']

        key_words_arr.extend([key_word.lower() for key_word in key_words_arr])
        _anomaly_words_arr.extend([key_word.lower() for key_word in _anomaly_words_arr])

        if packet.seq in self.__fin_arr or packet.ack in self.__packet_dict:
            return

        for anomaly_word in _anomaly_words_arr:
            if packet.seq in self.__packet_dict:
                break
            elif key_word in payload:
                n = payload.find(key_word)
                payload = payload[n::]
                e = min(payload.find('\x00'), payload.find('\x01'))
                payload = payload[:e:]
                self.__even_logger.print_event(sql_text=payload,
                                                verdict=-1, ip=packet.payload.src) 

        for key_word in key_words_arr:
            if key_word in payload:
                n = payload.find(key_word)
                payload = payload[n::]
                e = min(payload.find('\x00'), payload.find('\x01'))
                payload = payload[:e:]
                packet_info_struct = self.__create_packet_info_struct(packet)                
                self.__packet_dict[packet.ack] = payload               

        if packet.seq in self.__packet_dict:
            sql_query = self.__packet_dict[packet.seq]
            parser = sql_parser(sql_query)
            vector = parser.get_lexeme_count_dict()
            vector['attr_count'] = parser.get_attribute_count()
            vector['rel_count'] = parser.get_relations_count()
            sampled_data = parser.get_sampled_attribute_count()
            vector['sampled_attr_count'] = sampled_data[0]
            vector['sampled_rel_count'] = sampled_data[1]      
            vector['len'] = len(sql_query)
            vector['response_len'] = len(payload)     

            if self.__train_mode:
                file = open(self.__train_mode + '_data.csv','a')                            
                writer = csv.DictWriter(file, fieldnames=vector.keys())
                writer.writerow(vector)                                         
                file.close()
            else:
                analyzer = rf_analyzer('random_forest_model.sav')                
                verdict = analyzer.analyze(vector.values())
                self.__even_logger.print_event(sql_text=self.__packet_dict[packet.seq],
                                                verdict=verdict, ip=packet.payload.dst)                 

            self.__fin_arr.append(packet.seq)

    def __process_packets(self, packet):
        """
        Saves TNS packets and updates session list

        :param packet: Captured TNS packet
        """        
        self.__analyze_packet(packet)

        if len(self.__packet_dict) % self.__session_list_update_value == 0:
            self.__update_session_list()

    def sniff_packets(self):
        """
        Sniffs TNS packets in local network
        """
        filter_str = '(dst port ' + self.__oracle_server_port + ' or src port ' + self.__oracle_server_port + ') and tcp and ' + '(not (host ' + self.__ids_ip + '))'
        scapy.sniff(iface=self.__iface_name,
                    filter=filter_str,
                    session=scapy.TCPSession,
                    store=False,
                    prn=self.__process_packets
                    )
