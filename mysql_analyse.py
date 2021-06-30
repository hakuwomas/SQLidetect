from mysql_traffic import mysql_traffic_analyzer

train_mode = None

# ots = oracle_traffic_analyzer('ens33', '192.168.14.142', 1521, train_mode=[True, train_mode + '_activity'])
ots = mysql_traffic_analyzer('ens38', '192.168.10.1', 3306)
ots.sniff_packets()