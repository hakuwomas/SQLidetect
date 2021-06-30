from mssql_traffic import mssql_traffic_analyzer

train_mode = 'legal'

# ots = mssql_traffic_analyzer('ens33', '192.168.14.142', 1521, train_mode=[True, train_mode + '_activity'])
ots = mssql_traffic_analyzer('ens38', '192.168.10.1', 1433, train_mode=train_mode)
ots.sniff_packets()