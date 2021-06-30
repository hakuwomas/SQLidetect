from oracle_traffic import oracle_traffic_analyzer
from mssql_traffic import mssql_traffic_analyzer
from mysql_traffic import mysql_traffic_analyzer
from pg_traffic import pg_traffic_analyzer

import sys


if __name__ == '__main__':
    if len(sys.argv) < 5:
        print('Usage format: python dbs_ids.py <oracle|mssql|pgsql|mysql> <iface> <server_addr> <server_port>')
        exit(0)

    if sys.argv[1].lower() == 'oracle':
        try:
            ots = oracle_traffic_analyzer(sys.argv[2], sys.argv[3], int(sys.argv[4]))
            print('Analyzer for {dbs_name} successfully initialized.'.format(dbs_name=sys.argv[1]))
            ots.sniff_packets()                
        except:
            print("Can't initialize analyzer for {dbs_name}".format(dbs_name=sys.argv[1]))
        exit(0)

    if sys.argv[1].lower() == 'mysql':
        try:
            myts = mysql_traffic_analyzer(sys.argv[2], sys.argv[3], int(sys.argv[4]))
            print('Analyzer for {dbs_name} successfully initialized.'.format(dbs_name=sys.argv[1]))
            myts.sniff_packets()        
        except:
            print("Can't initialize analyzer for {dbs_name}".format(dbs_name=sys.argv[1]))
        exit(0)
			
    if sys.argv[1].lower() == 'pgsql':
        try:
            pgts = pg_traffic_analyzer(sys.argv[2], sys.argv[3], int(sys.argv[4]))
            print('Analyzer for {dbs_name} successfully initialized.'.format(dbs_name=sys.argv[1]))
            pgts.sniff_packets()        
        except:
            print("Can't initialize analyzer for {dbs_name}".format(dbs_name=sys.argv[1]))
        exit(0)

    if sys.argv[1].lower() == 'mssql':
        try:
            msts = mssql_traffic_analyzer(sys.argv[2], sys.argv[3], int(sys.argv[4]))
            print('Analyzer for {dbs_name} successfully initialized.'.format(dbs_name=sys.argv[1]))
            msts.sniff_packets()            
        except:
            print("Can't initialize analyzer for {dbs_name}".format(dbs_name=sys.argv[1]))
        exit(0)

