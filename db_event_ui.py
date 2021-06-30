import os

class db_event_ui:
    def __init__(self, db_name):
        self.__db_name = db_name
        self.__block_ip_arr = []
        f = open("block_ip.txt", "r")
        for line in f:
            self.__block_ip_arr.append(line)
        f.close()

    def print_event(self, sql_text, verdict, ip):
        if ip in self.__block_ip_arr:
            return

        print("""
        {db_name} SQL query captured: {sql_text}
        Verdict: {verdict}""".format(db_name=self.__db_name,
                   sql_text=sql_text,
                   verdict='normal' if verdict == 1 else 'anomaly'))
        if verdict == -1:
            command = raw_input('\t\tBlock user ' + ip + ' ?[y/n]')
            if command == 'y':
                self.__block_ip_arr.append(ip)
                f = open("block_ip.txt", "a")
                f.write(ip + "\n")
                f.close()
                os.system('iptables -A FORWARD -s ' + ip + ' -j DROP')
                print('\t\tUser has been blocked')
            if command == 'n':
                print('\t\tIgnore')



