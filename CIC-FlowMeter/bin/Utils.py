import os
import pandas as pd
import numpy as np
import logging
from datetime import datetime
import socket
from binascii import hexlify
import subprocess
import threading
import DbSetUp as db
import struct
import netaddr
import re
from blaze import data

numeric_types = [int, float, complex]

#layer indicators
#(this reads the already existent ones and reopens the file for possible updates)
highestLayerVersions = open("varianteHighestLayer.txt","r")
trafficLayerVersions = open("varianteTrafficLayer.txt", "r")

contents = highestLayerVersions.read()
highestLayer = list(filter(None, contents.split(", ")))
contents = trafficLayerVersions.read()
trafficLayer = list(filter(None, contents.split(", ")))

highestLayerVersions.close()
trafficLayerVersions.close()

highestLayerVersions = open("varianteHighestLayer.txt","a")
trafficLayerVersions = open("varianteTrafficLayer.txt", "a")

whitelist = ['192.168.178.141', '']
packetNamez = ['Source Port', 'Dest Port', 'Packet Length', 'Packets/Time', 'Source IP', 'Dest IP', 'Highest Layer', 'Transport Layer']
packetNames = ['Source Port', 'Dest Port', 'Packet Length', 'Packets/Time', 'Source IP', 'Dest IP', 'Highest Layer', 'Transport Layer']
flowNames = []

logger = logging.getLogger()

def setFlowNames(names):
    global flowNames
    flowNames = names

def getFlowNames():
    global flowNames
    return flowNames

'''
    get interfaces names
    by looking in the /sys/class/net/ file
'''
def interface_names():
    return os.listdir('/sys/class/net/')

'''
    close layer versions files
'''
def closeVers():
    global highestLayerVersions, trafficLayerVersions
    highestLayerVersions.close()
    trafficLayerVersions.close()

'''
    return the packet names for training data
'''
def getPacketNames():
    global packetNamez
    return packetNamez

'''
    add trafficLayer and highestLayer elements if they were not existent in prior
    recorded traffic
    and return the index position in the array which will represent the numerical
    encoding in the model
'''
def addLayers(toEncode, high, traffic):
    global highestLayer, highestLayerVersions, trafficLayer, trafficLayerVersions
    if toEncode[high] not in highestLayer:
        highestLayer.append(toEncode[high])
        highestLayerVersions.write(str(toEncode[high])+", ")
    if toEncode[traffic] not in trafficLayer:
        trafficLayer.append(toEncode[traffic])
        trafficLayerVersions.write(str(toEncode[traffic])+", ")
    return [highestLayer.index(toEncode[high]), trafficLayer.index(toEncode[traffic])]

'''
    one hot encoding for binary ipv4 address
'''
def transform_ip(ip):
    global numeric_types
    b = []
    if type(ip) in numeric_types:
        b = [ j for j in str('{0:08b}'.format(ip))]
        b += [j for j in '000000000000000000000000']
    else:
        a = ip.split(".")
        if a == [ip]:
            c = str(hexlify(socket.inet_pton(socket.AF_INET6, ip)))
            c = c[2:34]
            for i in range(len(c)) :
                b += [str(int(c[i], 16))]
        else:
            for i in range(4):
                b += [ j for j in str('{0:08b}'.format(int(a[i])))]
    return b

def one_hot_ipF(df, name_file):
    name = [name_file +" bit"+str(i) for i in range(32)]
    ip_df = df[name_file].apply( lambda ip: transform_ip(ip) ).apply( pd.Series ).apply(pd.to_numeric)
    ip_df.columns = name
    return ip_df

'''
    creates 32 bit representation of IP address
'''
def one_hot_ip(df, name_file):
    ip_df = [ int(x) for x in transform_ip(df[name_file])]
    '''else:
        name = [name_file +" bit"+str(i) for i in range(32)]
        ip_df = df[name_file].apply( lambda ip: transform_ip(ip) ).apply( pd.Series ).apply(pd.to_numeric)
        ip_df.columns = name
        print(ip_df)'''
    return ip_df

'''
    returns the target specific for the training data
'''
def get_Target(x):
    if str(x) == "b\'Normal\'" :
        return False
    else:
        return True

def get(v):
    a = [[t] for t in v]
    return a

'''
    converts an ip into an integer
'''
def ip2int(addr):
    return int(netaddr.IPAddress(addr))

'''
    Converts time to numerical
'''
def time_to_nb(time):
    names = ["Date", "Month", "Year", "Hour", "Minute", "Second", "Mark"]
    a = [list(filter(None, re.findall(r"[\w']*", t))) for t in time]
    ok = 0
    for i in a:
        if len(i) == 6:
            ok == 1
            break
    if ok == 0:
        time_df = pd.DataFrame(a, columns=names)
        mask = time_df.Mark == "PM"
        column_name = 'Hour'
        time_df.loc[mask, column_name] = pd.to_numeric(time_df.Hour) + 12
        time_df = time_df.drop(['Mark'], axis=1)
        time_df = time_df.apply(pd.to_numeric)
        #for i in range(6):
         # time_df[names[i]] = pd.to_numeric(time_df[names[i]])
        return time_df
    names = ["Date", "Month", "Year", "Hour", "Minute", "Second"]
    time_df = pd.DataFrame(a, columns=names)
    time_df = time_df.apply(pd.to_numeric)
    return time_df

'''
    returns a number corresponding to a class
'''
def get_Type_Coding(x):
    if str(x) == "b\'tcp\'":
        return 1
    elif str(x) == "b\'ack\'":
        return 2
    elif str(x) == "b\'cbr\'":
        return 3
    elif str(x) == "b\'ping\'":
        return 4
    else:
        return 0

'''
    sets the global logger
'''
def setLogger(logg):
    global logger
    logger = logg

'''
    get the global logger
'''
def getLogger():
    global logger
    return logger

'''
    Add an Ip address to the list of blocked Ip-addresses
'''
def blockIp(ip, flowId, port, origin):
    global logger
    db.insert_BlockedIp(flowId, ip, port, origin)
    #cmd = 'sudo -S /sbin/iptables -A INPUT -s ' + ip + ' -j DROP'
    logger.info("The " + ip + " ip address was blocked due to a DDoS attack")
    #subprocess.call(cmd, shell = True)

'''
    List the blocked Ip-addresses
'''
def listBlockedIps():
    subprocess.call(["sudo", "-S", "iptables", "-L", "-n"])

'''
    Delete the listed Ip from the blocked IP-addresses
'''
def unblockIp(ip):
    subprocess.call(["sudo", "-S", "/sbin/iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])


'''
    converts the time stored in the layer fields container into a proper get_datetime
    The time corresponds to the time the packet was recorded
'''
def get_datetime(date):
    months = ['Month', 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    elems = date.split(' ')
    times = elems[3].split(":")
    sec = times[2].split(".")
    mili = int(int(sec[1])/1000)
    return datetime(int(elems[2]), months.index(elems[0]), int(elems[1].split(',')[0]), int(times[0]), int(times[1]), int(sec[0]), mili)


'''
    return flowId
    #SrcIp-DstIp-SrcPort-DstPort-Protocol
'''
def getFlowId(SrcIp, DstIp, SrcPort, DstPort, Protocol):
    return str(SrcIp) + '-' + str(DstIp) + '-' + str(SrcPort) + '-' + str(DstPort) + '-' + str(Protocol)

def to_one_hot_encoding(df):
    return pd.concat([df, one_hot_ipF(df,'Src IP'), one_hot_ipF(df, 'Dst IP'), time_to_nb(df['Timestamp'])], axis=1, sort=False)


'''
    Encode the categorical traffic data into integer values
'''
def labelEncoder(data, types):
    global logger
    global numeric_types, packetNames
    logger.info("Encoding categorical packet data")
    encoded = []
    toEncode = []
    if types == 'LiveCapture':
        #only src_ip, dst_ip, highest_layer, and transport_layer will remain
        toEncode = [x for x in data if type(x) not in numeric_types]
        numeric = [x for x in data if type(x) in numeric_types]
        encoded =  numeric + [ip2int(toEncode[0])] + [ip2int(toEncode[1])] + addLayers(toEncode, 2, 3)
        return pd.DataFrame([encoded], columns=packetNames), toEncode
    else:
        toEncode = data[['Source IP', 'Dest IP', 'Highest Layer', 'Transport Layer']]
        numeric = data[['Source Port', 'Dest Port', 'Packet Length', 'Packets/Time']]
        encoded = numeric.tolist() + [ip2int(toEncode['Source IP'])] + [ip2int(toEncode['Dest IP'])] + addLayers(toEncode, 'Highest Layer', 'Transport Layer')
        return pd.Series(encoded), toEncode
    return pd.DataFrame([encoded], columns=packetNames), toEncode


'''
    return whether the packet was captured in ipv4 or ipv6
'''
def get_ipvx(packet):
    for layer in packet.layers:
        if layer._layer_name == 'ip':
            return 4
        elif layer._layer_name =='ipv6':
            return 6
    return None


'''
    return the proper ip version
'''
def get_ip(packet):
    ip = get_ipvx(packet)
    if ip == 4:
        return packet.ip
    elif ip == 6:
        return packet.ipv6
    return None

'''
    waits for all the packet checks used for the training to end
'''
def join_checks(count):
    global logger
    print("this many active threads "+ str(threading.active_count()))
    for t in threading.enumerate():
        if 'check_packet' not in t.name:
            print(t.name)
            pass
        elif int(t.name.replace('check_packet','')) <= count:
            logger.warning("Waiting for the join " + t.name)
            t.join()

'''
    return flow columns
'''
def getFlowCols():
    return ['id','Flow_ID', 'Src_IP', 'Src_Port', 'Dst_IP', 'Dst_Port', 'Protocol',
        'Timestamp', 'Flow_Duration', 'Tot_Fwd_Pkts', 'Tot_Bwd_Pkts', 'TotLen_Fwd_Pkts',
        'TotLen_Bwd_Pkts', 'Fwd_Pkt_Len_Max', 'Fwd_Pkt_Len_Min', 'Fwd_Pkt_Len_Mean',
        'Fwd_Pkt_Len_Std', 'Bwd_Pkt_Len_Max', 'Bwd_Pkt_Len_Min', 'Bwd_Pkt_Len_Mean',
        'Bwd_Pkt_Len_Std', 'Flow_Bytss', 'Flow_Pktss', 'Flow_IAT_Mean', 'Flow_IAT_Std',
        'Flow_IAT_Max', 'Flow_IAT_Min', 'Fwd_IAT_Tot', 'Fwd_IAT_Mean', 'Fwd_IAT_Std',
        'Fwd_IAT_Max', 'Fwd_IAT_Min', 'Bwd_IAT_Tot', 'Bwd_IAT_Mean', 'Bwd_IAT_Std',
        'Bwd_IAT_Max', 'Bwd_IAT_Min', 'Fwd_PSH_Flags', 'Bwd_PSH_Flags', 'Fwd_URG_Flags',
        'Bwd_URG_Flags', 'Fwd_Header_Len', 'Bwd_Header_Len', 'Fwd_Pktss', 'Bwd_Pktss',
        'Pkt_Len_Min', 'Pkt_Len_Max', 'Pkt_Len_Mean', 'Pkt_Len_Std', 'Pkt_Len_Var',
        'FIN_Flag_Cnt', 'SYN_Flag_Cnt', 'RST_Flag_Cnt', 'PSH_Flag_Cnt', 'ACK_Flag_Cnt',
        'URG_Flag_Cnt', 'CWE_Flag_Count', 'ECE_Flag_Cnt', 'Down_Up_Ratio', 'Pkt_Size_Avg',
        'Fwd_Seg_Size_Avg', 'Bwd_Seg_Size_Avg', 'Fwd_Bytsb_Avg', 'Fwd_Pktsb_Avg',
        'Fwd_Blk_Rate_Avg', 'Bwd_Bytsb_Avg', 'Bwd_Pktsb_Avg', 'Bwd_Blk_Rate_Avg',
        'Subflow_Fwd_Pkts', 'Subflow_Fwd_Byts', 'Subflow_Bwd_Pkts', 'Subflow_Bwd_Byts',
        'Init_Fwd_Win_Byts', 'Init_Bwd_Win_Byts', 'Fwd_Act_Data_Pkts', 'Fwd_Seg_Size_Min',
        'Active_Mean', 'Active_Std', 'Active_Max', 'Active_Min', 'Idle_Mean',
        'Idle_Std', 'Idle_Max', 'Idle_Min', 'Label', 'Received_Time', 'Predicted_Time',
        'Handled_Time']

'''
    compute the probabilities that a certain flow is a ddos attack or not
    based on the analysis made at the problem level
    for all matching Flow_IDs you compute the percentage that it was detected as
    a DDoS attack; if that percentage exceedes 50% then you mark it with 1
    otherwise with 0
'''
def getTargets(packets, flows):
    ids = [x for x in packets['Flow_ID'].unique()]
    fin = {}
    for i in ids:
        pack = np.array(packets[(packets['Flow_ID'] == i)]['Predict'])
        flo = np.array(flows[(flows['Flow_ID'] == i)]['Label'])
        if int(sum(pack)+sum(flo))*100/(len(pack)+len(flo)) >= 50:
            fin[i] = 1
        else:
            fin[i] = 0
    finPack = np.array(list(fin[i] for i in packets['Flow_ID']))
    return finPack

'''
    compute the probabilities that a certain flow is a ddos attack or not
    based on the analysis made at the problem level
    for all matching Flow_IDs you compute the percentage that it was detected as
    a DDoS attack; if that percentage exceedes 50% then you mark it with 1
    otherwise with 0
'''
def getTargetsF(flows, packets):
    ids = [x for x in flows['Flow_ID'].unique()]
    fin = {}
    for i in ids:
        pack = np.array(packets[(packets['Flow_ID'] == i)]['Predict'])
        flo = np.array(flows[(flows['Flow_ID'] == i)]['Label'])
        if int(sum(pack)+sum(flo))*100/(len(pack)+len(flo)) >= 50:
            fin[i] = 1
        else:
            fin[i] = 0
    finPack = np.array(list(fin[i] for i in flows['Flow_ID']))
    return finPack

#Everything under is not used due to issues with software used
'''
    Use CICFlowMeter to generate the flow corresponding to the read traffic

def get_flow_spec(threadNb):
    file = "traffic"+threadNb
    cmd = ['./cfm \"'+file+'.pcap\" \"traffic.csv\"']
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    p.wait()
'''
