import influxdb
import sys
import pandas as pd

headers_entropy = ['total_packets',
                   'tcp_packets',
                   'tcp_syn_packets',
                   'udp_packets',
                   'icmp_packets',
                   'avg_len',
                   'entropy_src_ip',
                   'entropy_src_port',
                   'label']
database = {
    "entropy" : ("ddos_entropy","ddos")
}

QUERY_ENTROPY = """select * from ddos order by time desc limit 3000"""

class MetricCollecter:
    def __init__(self, db_host = 'localhost', port = 8086, db = 'telegraf', measure_name = None, measurement_class = None, out_file = None, label = None):
        self.host = db_host
        self.port = port
        self.dbname = db
        self.measure_name = measure_name
        self.measurement_class = measurement_class
        self.out_file = out_file
        self.label = label
        self.client = influxdb.InfluxDBClient(self.host,self.port, 'telegraf', 'telegraf', 'ddos')

    def collect(self,q):
        dataframe = []
        for measurement in self.client.query(q).get_points(measurement = self.measure_name):
            data = []
            data.append(measurement['total_packets'])
            data.append(measurement['tcp_packets'])
            data.append(measurement['tcp_syn_packets'])
            data.append(measurement['udp_packets'])
            data.append(measurement['icmp_packets'])
            data.append(measurement['avg_len'])
            data.append(measurement['entropy_src_ip'])
            data.append(measurement['entropy_src_port'])
            data.append(self.label)
            dataframe.append(data)
        dataframe = pd.DataFrame(dataframe, columns = headers_entropy)
        dataframe.to_csv(self.out_file, index = False)

def actions(database_type, measure):

    db_name, measure_n = database[database_type]
    if measure == "0":
        file_name = "normal"
    else: 
        file_name = "attack"
    collector = MetricCollecter(db = db_name,
                                measure_name = measure_n,
                                measurement_class = measure,
                                out_file = f"DDoS_data_{file_name}.csv",
                                label = measure)

    if database_type == "entropy":
        collector.collect(QUERY_ENTROPY)

if __name__ == "__main__":

    try:
        measurement_class = sys.argv[1]
    except IndexError as e:
        print("Measurement class not provided: {}".format(e))

    actions('entropy', measurement_class)
    print("Finished generating a label = {} training dataset!".format(measurement_class))


