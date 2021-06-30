from pg_traffic import pg_traffic_analyzer

train_mode = 'anomaly'

# ots = oracle_traffic_analyzer('ens33', '192.168.14.142', 1521, train_mode=[True, train_mode + '_activity'])
ots = pg_traffic_analyzer('ens38', '192.168.10.1', 5432, train_mode=train_mode)
ots.sniff_packets()
