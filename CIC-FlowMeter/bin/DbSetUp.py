import mysql.connector
import logging
import Utils as utils
from decimal import *
import math

slot_interval = 30 #seconds

def dropTable(name):
    sql_command = """
    DROP TABLE name;
    """
    return sql_command.replace('name', name)

'''
    Database containing all blocked addresses
'''
def get_blocked_command():
    sql_command='''
    CREATE TABLE IF NOT EXISTS blockedIp (
        id INT AUTO_INCREMENT PRIMARY KEY,
        Flow_ID VARCHAR(255),
        IP VARCHAR(255),
        Port INT,
        Origin VARCHAR(255)
    );
    '''
    return sql_command

# to change back to normal names
# change _ with space and
# ss and sb with s/s && s/b
def get_flow_command(name):
    sql_command = """
    CREATE TABLE IF NOT EXISTS name (
      id INT AUTO_INCREMENT PRIMARY KEY,
      Flow_ID VARCHAR(255),
      Src_IP VARCHAR(255),
      Src_Port INT,
      Dst_IP VARCHAR(255),
      Dst_Port INT,
      Protocol INT,
      Timestamp VARCHAR(255),
      Flow_Duration INT,
      Tot_Fwd_Pkts INT,
      Tot_Bwd_Pkts INT,
      TotLen_Fwd_Pkts DECIMAL,
      TotLen_Bwd_Pkts DECIMAL,
      Fwd_Pkt_Len_Max DECIMAL,
      Fwd_Pkt_Len_Min DECIMAL,
      Fwd_Pkt_Len_Mean DECIMAL,
      Fwd_Pkt_Len_Std DECIMAL,
      Bwd_Pkt_Len_Max DECIMAL,
      Bwd_Pkt_Len_Min DECIMAL,
      Bwd_Pkt_Len_Mean DECIMAL,
      Bwd_Pkt_Len_Std DECIMAL,
      Flow_Bytss DECIMAL,
      Flow_Pktss DECIMAL,
      Flow_IAT_Mean DECIMAL,
      Flow_IAT_Std DECIMAL,
      Flow_IAT_Max DECIMAL,
      Flow_IAT_Min DECIMAL,
      Fwd_IAT_Tot DECIMAL,
      Fwd_IAT_Mean DECIMAL,
      Fwd_IAT_Std DECIMAL,
      Fwd_IAT_Max DECIMAL,
      Fwd_IAT_Min DECIMAL,
      Bwd_IAT_Tot DECIMAL,
      Bwd_IAT_Mean DECIMAL,
      Bwd_IAT_Std DECIMAL,
      Bwd_IAT_Max DECIMAL,
      Bwd_IAT_Min DECIMAL,
      Fwd_PSH_Flags INT,
      Bwd_PSH_Flags INT,
      Fwd_URG_Flags INT,
      Bwd_URG_Flags INT,
      Fwd_Header_Len INT,
      Bwd_Header_Len INT,
      Fwd_Pktss DECIMAL,
      Bwd_Pktss DECIMAL,
      Pkt_Len_Min DECIMAL,
      Pkt_Len_Max DECIMAL,
      Pkt_Len_Mean DECIMAL,
      Pkt_Len_Std DECIMAL,
      Pkt_Len_Var DECIMAL,
      FIN_Flag_Cnt INT,
      SYN_Flag_Cnt INT,
      RST_Flag_Cnt INT,
      PSH_Flag_Cnt INT,
      ACK_Flag_Cnt INT,
      URG_Flag_Cnt INT,
      CWE_Flag_Count INT,
      ECE_Flag_Cnt INT,
      Down_Up_Ratio DECIMAL,
      Pkt_Size_Avg DECIMAL,
      Fwd_Seg_Size_Avg DECIMAL,
      Bwd_Seg_Size_Avg DECIMAL,
      Fwd_Bytsb_Avg DECIMAL,
      Fwd_Pktsb_Avg DECIMAL,
      Fwd_Blk_Rate_Avg DECIMAL,
      Bwd_Bytsb_Avg DECIMAL,
      Bwd_Pktsb_Avg DECIMAL,
      Bwd_Blk_Rate_Avg DECIMAL,
      Subflow_Fwd_Pkts INT,
      Subflow_Fwd_Byts INT,
      Subflow_Bwd_Pkts INT,
      Subflow_Bwd_Byts INT,
      Init_Fwd_Win_Byts INT,
      Init_Bwd_Win_Byts INT,
      Fwd_Act_Data_Pkts INT,
      Fwd_Seg_Size_Min INT,
      Active_Mean DECIMAL,
      Active_Std DECIMAL,
      Active_Max DECIMAL,
      Active_Min DECIMAL,
      Idle_Mean DECIMAL,
      Idle_Std DECIMAL,
      Idle_Max DECIMAL,
      Idle_Min DECIMAL,
      Label INT,
      Received_Time VARCHAR(250),
      Predicted_Time DECIMAL,
      Handled_Time DECIMAL
      );
      """
    return sql_command.replace('name', name)

def get_packets_command(name):
    sql_command = """
    CREATE TABLE IF NOT EXISTS name (
            id INT AUTO_INCREMENT PRIMARY KEY,
            Flow_ID VARCHAR(255),
            Src_IP VARCHAR(255),
            Src_Port INT,
            Dst_IP VARCHAR(255),
            Dst_Port INT,
            Protocol INT,
            Pkt_Len INT,
            Packets_Time DECIMAL,
            Highest_Layer VARCHAR(255),
            Traffic_Layer VARCHAR(255),
            Received_Time DECIMAL,
            Predicted_Time DECIMAL,
            Handled_Time DECIMAL,
            Predict INT
            );"""
    return sql_command.replace('name', name)

def main():
    mydb = mysql.connector.connect(
    host = "localhost",
    user = "root",
    passwd= "password",
    )
    mycursor = mydb.cursor()
    mycursor.execute("DROP DATABASE IF EXISTS mlpLive;")
    mycursor.execute("CREATE DATABASE IF NOT EXISTS mlpLive;")

    mydb = mysql.connector.connect(
    host = "localhost",
    user = "root",
    passwd= "password",
    database= "mlpLive",
    )
    mycursor = mydb.cursor()

    mycursor.execute(get_packets_command('finalPackets'))
    mycursor.execute(get_packets_command('newPackets1'))
    mycursor.execute(get_packets_command('newPackets2'))
    mycursor.execute(get_packets_command('newPackets0'))
    mycursor.execute(get_flow_command('finalFlow'))
    mycursor.execute(get_flow_command('newFlow1'))
    mycursor.execute(get_flow_command('newFlow2'))
    mycursor.execute(get_flow_command('newFlow0'))
    mycursor.execute(get_blocked_command())

    mycursor.close()
    mydb.close()

# main() # run main to create database

'''
    Everything under here are sql operations required in mlpLive
'''

'''
    get database and cursor
'''
def getdb_cursor():
    mydb = mysql.connector.connect(
    host = "localhost",
    user = "root",
    passwd= "password",
    database= "mlpLive",
    autocommit= True,
    )
    mycursor = mydb.cursor()
    return mydb, mycursor

'''
    Delete elements from packets table
'''
def deletePTable(name, mycursor, mydb):
    sql_command = """
    DELETE FROM name;
    COMMIT;
    """
    logger = utils.getLogger()
    try:
        mycursor.execute(sql_command.replace('name', name), multi=True)
        mydb.commit()
        print("Deleted packets from the {} database".format(name))
    except mysql.connector.Error as error:
        mydb.rollback()
        logger.error("An error occurred while deleting the values from {} ".format(name)+ error)
    except Exception as e:
        logger.error("Exception occurred", exc_info=True)
        print(e)

'''
    Delete elements from flow table
'''
def deleteFTable(name, mycursor, mydb):
    sql_command = """
    DELETE FROM name;
    COMMIT;
    """
    logger = utils.getLogger()
    try:
        mycursor.execute(sql_command.replace('name', name), multi=True)
        mydb.commit()
        print("Deleted flows from the {} database".format(name))
    except mysql.connector.Error as error:
        mydb.rollback()
        logger.error("An error occurred while deleting the values from {} ".format(name)+ error)
    except Exception as e:
        logger.error("Exception occurred", exc_info=True)
        print(e)

'''
    Insert working flow table into final flow table
'''
def insertFTable(name):
    mydb, mycursor = getdb_cursor()
    sql_command = """
    INSERT INTO finalFlow
    SELECT * FROM name;
    """
    logger = utils.getLogger()
    try:
        mycursor.execute(sql_command.replace('name', name), multi=True)
        deletePTable(name, mycursor, mydb)
        mydb.commit()
        print("Managed to insert into finalFlow the flows from {} database".format(name))
    except mysql.connector.Error as error:
        mydb.rollback()
        logger.error("An error occurred while inserting the flow into the final Table: "+ error)
    except Exception as e:
        logger.error("Exception occurred", exc_info=True)
        print(e)
    finally:
        if mydb.is_connected():
            mycursor.close()
            mydb.close()
            logger.info("Connection is closed")

'''
    Insert working packets table into final packets table
'''
def insertPTable(name):
    mydb, mycursor = getdb_cursor()
    sql_command = """
    INSERT INTO finalPackets
    SELECT * FROM name;
    """
    logger = utils.getLogger()
    try:
        mycursor.execute(sql_command.replace('name', name), multi=True)
        deletePTable(name, mycursor, mydb)
        mydb.commit()
        print("Managed to insert into finalPackets the packets from {} database".format(name))
    except mysql.connector.Error as error:
        mydb.rollback()
        logger.error("An error occurred while inserting the packets into the final Table: "+ error)
    except Exception as e:
        logger.error("Exception occurred", exc_info=True)
        print(e)
    finally:
        if mydb.is_connected():
            mycursor.close()
            mydb.close()
            logger.info("Connection is closed")

'''
    Inserts the information used for retraining into a chosen training database
'''
def insert_packet(data, nonNumeric, protocol, prediction, receivedTime, predictedTime, handledTime, name):
    mydb, mycursor = getdb_cursor()
    #SrcIp-DstIp-SrcPort-DstPort-Protocol
    Flow_ID = utils.getFlowId(nonNumeric[1], nonNumeric[0], int(data['Dest Port']), int(data['Source Port']), str(protocol))
    insert_query = """
    INSERT INTO name (
        id,
        Flow_ID,
        Src_IP,
        Src_Port,
        Dst_IP,
        Dst_Port,
        Protocol,
        Pkt_Len,
        Packets_Time,
        Highest_Layer,
        Traffic_Layer,
        Received_Time,
        Predicted_Time,
        Handled_Time,
        Predict)
    VALUES (DEFAULT,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
    logger = utils.getLogger()
    try:
        info = (Flow_ID,
            str(nonNumeric[0]),
            str(int(data['Source Port'])),
            str(nonNumeric[1]),
            str(int(data['Dest Port'])),
            str(protocol),
            str(int(data['Packet Length'])),
            str(Decimal(float(data['Packets/Time']))),
            str(nonNumeric[2]),
            str(nonNumeric[3]),
            str(receivedTime),
            str(Decimal(predictedTime)),
            str(Decimal(handledTime)),
            str(int(prediction)))
        mycursor.execute(insert_query.replace('name', name), info)
        logger.info("Record inserted successfully into " + name + " table")
        mydb.commit()
    except mysql.connector.Error as error:
        mydb.rollback()
        logger.error("An error occurred while inserting a packet: "+ str(error))
    except Exception as error:
        logger.error("Exception occurred", exc_info=True)
    finally:
        if mydb.is_connected():
            mycursor.close()
            mydb.close()
            logger.info("Connection is closed")


'''
    Saves information about the blocked ip addresses
'''
def insert_BlockedIp(Flow_ID, ip, port, origin):
    mydb, mycursor = getdb_cursor()
    insert_query = """
    INSERT INTO blockedIp (
        id,
        Flow_ID,
        IP,
        Port,
        Origin)
    VALUES (DEFAULT,%s,%s,%s,%s)
    """

    logger = utils.getLogger()
    try:
        info = (Flow_ID, str(ip), str(port), origin)
        mycursor.execute(insert_query, info)
        logger.info("Record inserted successfully into blockedIp table")
        mydb.commit()
    except mysql.connector.Error as error:
        mydb.rollback()
        logger.error("An error occurred while inserting a packet: "+ error)
    except Exception as error:
        logger.error("Exception occurred", exc_info=True)
    finally:
        if mydb.is_connected():
            mycursor.close()
            mydb.close()
            logger.info("Connection is closed")


'''
    insert flow into specified database
'''
def insertFlow(data, prediction, receivedT, predT, handT, name):
    mydb, mycursor = getdb_cursor()
    insert_query = """
    INSERT INTO name (
        id,
        Flow_ID,
        Src_IP,
        Src_Port,
        Dst_IP,
        Dst_Port,
        Protocol,
        Timestamp,
        Flow_Duration,
        Tot_Fwd_Pkts,
        Tot_Bwd_Pkts,
        TotLen_Fwd_Pkts,
        TotLen_Bwd_Pkts,
        Fwd_Pkt_Len_Max,
        Fwd_Pkt_Len_Min,
        Fwd_Pkt_Len_Mean,
        Fwd_Pkt_Len_Std,
        Bwd_Pkt_Len_Max,
        Bwd_Pkt_Len_Min,
        Bwd_Pkt_Len_Mean,
        Bwd_Pkt_Len_Std,
        Flow_Bytss,
        Flow_Pktss,
        Flow_IAT_Mean,
        Flow_IAT_Std,
        Flow_IAT_Max,
        Flow_IAT_Min,
        Fwd_IAT_Tot,
        Fwd_IAT_Mean,
        Fwd_IAT_Std,
        Fwd_IAT_Max,
        Fwd_IAT_Min,
        Bwd_IAT_Tot,
        Bwd_IAT_Mean,
        Bwd_IAT_Std,
        Bwd_IAT_Max,
        Bwd_IAT_Min,
        Fwd_PSH_Flags,
        Bwd_PSH_Flags,
        Fwd_URG_Flags,
        Bwd_URG_Flags,
        Fwd_Header_Len,
        Bwd_Header_Len,
        Fwd_Pktss,
        Bwd_Pktss,
        Pkt_Len_Min,
        Pkt_Len_Max,
        Pkt_Len_Mean,
        Pkt_Len_Std,
        Pkt_Len_Var,
        FIN_Flag_Cnt,
        SYN_Flag_Cnt,
        RST_Flag_Cnt,
        PSH_Flag_Cnt,
        ACK_Flag_Cnt,
        URG_Flag_Cnt,
        CWE_Flag_Count,
        ECE_Flag_Cnt,
        Down_Up_Ratio,
        Pkt_Size_Avg,
        Fwd_Seg_Size_Avg,
        Bwd_Seg_Size_Avg,
        Fwd_Bytsb_Avg,
        Fwd_Pktsb_Avg,
        Fwd_Blk_Rate_Avg,
        Bwd_Bytsb_Avg,
        Bwd_Pktsb_Avg,
        Bwd_Blk_Rate_Avg,
        Subflow_Fwd_Pkts,
        Subflow_Fwd_Byts,
        Subflow_Bwd_Pkts,
        Subflow_Bwd_Byts,
        Init_Fwd_Win_Byts,
        Init_Bwd_Win_Byts,
        Fwd_Act_Data_Pkts,
        Fwd_Seg_Size_Min,
        Active_Mean,
        Active_Std,
        Active_Max,
        Active_Min,
        Idle_Mean,
        Idle_Std,
        Idle_Max,
        Idle_Min,
        Label,
        Received_Time,
        Predicted_Time,
        Handled_Time)
    VALUES (DEFAULT,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """
    logger = utils.getLogger()
    try:
        info = (str(data["Flow ID"][0]),
        str(data["Src IP"][0]),
        str(int(data["Src Port"][0])),
        str(data["Dst IP"][0]),
        str(int(data["Dst Port"][0])),
        str(int(data["Protocol"][0])),
        str(data["Timestamp"][0]),
        str(int(data["Flow Duration"][0])),
        str(int(data["Tot Fwd Pkts"][0])),
        str(int(data["Tot Bwd Pkts"][0])),
        str(Decimal(data["TotLen Fwd Pkts"][0])),
        str(Decimal(data["TotLen Bwd Pkts"][0])),
        str(Decimal(data["Fwd Pkt Len Max"][0])),
        str(Decimal(data["Fwd Pkt Len Min"][0])),
        str(Decimal(data["Fwd Pkt Len Mean"][0])),
        str(Decimal(data["Fwd Pkt Len Std"][0])),
        str(Decimal(data["Bwd Pkt Len Max"][0])),
        str(Decimal(data["Bwd Pkt Len Min"][0])),
        str(Decimal(data["Bwd Pkt Len Mean"][0])),
        str(Decimal(data["Bwd Pkt Len Std"][0])),
        str(Decimal(data["Flow Byts/s"][0])),
        str(Decimal(data["Flow Pkts/s"][0])),
        str(Decimal(data["Flow IAT Mean"][0])),
        str(Decimal(data["Flow IAT Std"][0])),
        str(Decimal(data["Flow IAT Max"][0])),
        str(Decimal(data["Flow IAT Min"][0])),
        str(Decimal(data["Fwd IAT Tot"][0])),
        str(Decimal(data["Fwd IAT Mean"][0])),
        str(Decimal(data["Fwd IAT Std"][0])),
        str(Decimal(data["Fwd IAT Max"][0])),
        str(Decimal(data["Fwd IAT Min"][0])),
        str(Decimal(data["Bwd IAT Tot"][0])),
        str(Decimal(data["Bwd IAT Mean"][0])),
        str(Decimal(data["Bwd IAT Std"][0])),
        str(Decimal(data["Bwd IAT Max"][0])),
        str(Decimal(data["Bwd IAT Min"][0])),
        str(int(data["Fwd PSH Flags"][0])),
        str(int(data["Bwd PSH Flags"][0])),
        str(int(data["Fwd URG Flags"][0])),
        str(int(data["Bwd URG Flags"][0])),
        str(int(data["Fwd Header Len"][0])),
        str(int(data["Bwd Header Len"][0])),
        str(Decimal(data["Fwd Pkts/s"][0])),
        str(Decimal(data["Bwd Pkts/s"][0])),
        str(Decimal(data["Pkt Len Min"][0])),
        str(Decimal(data["Pkt Len Max"][0])),
        str(Decimal(data["Pkt Len Mean"][0])),
        str(Decimal(data["Pkt Len Std"][0])),
        str(Decimal(data["Pkt Len Var"][0])),
        str(int(data["FIN Flag Cnt"][0])),
        str(int(data["SYN Flag Cnt"][0])),
        str(int(data["RST Flag Cnt"][0])),
        str(int(data["PSH Flag Cnt"][0])),
        str(int(data["ACK Flag Cnt"][0])),
        str(int(data["URG Flag Cnt"][0])),
        str(int(data["CWE Flag Count"][0])),
        str(int(data["ECE Flag Cnt"][0])),
        str(Decimal(data["Down/Up Ratio"][0])),
        str(Decimal(data["Pkt Size Avg"][0])),
        str(Decimal(data["Fwd Seg Size Avg"][0])),
        str(Decimal(data["Bwd Seg Size Avg"][0])),
        str(Decimal(data["Fwd Byts/b Avg"][0])),
        str(Decimal(data["Fwd Pkts/b Avg"][0])),
        str(Decimal(data["Fwd Blk Rate Avg"][0])),
        str(Decimal(data["Bwd Byts/b Avg"][0])),
        str(Decimal(data["Bwd Pkts/b Avg"][0])),
        str(Decimal(data["Bwd Blk Rate Avg"][0])),
        str(int(data["Subflow Fwd Pkts"][0])),
        str(int(data["Subflow Fwd Byts"][0])),
        str(int(data["Subflow Bwd Pkts"][0])),
        str(int(data["Subflow Bwd Byts"][0])),
        str(int(data["Init Fwd Win Byts"][0])),
        str(int(data["Init Bwd Win Byts"][0])),
        str(int(data["Fwd Act Data Pkts"][0])),
        str(int(data["Fwd Seg Size Min"][0])),
        str(Decimal(data["Active Mean"][0])),
        str(Decimal(data["Active Std"][0])),
        str(Decimal(data["Active Max"][0])),
        str(Decimal(data["Active Min"][0])),
        str(Decimal(data["Idle Mean"][0])),
        str(Decimal(data["Idle Std"][0])),
        str(Decimal(data["Idle Max"][0])),
        str(Decimal(data["Idle Min"][0])),
        str(int(prediction)),
        str(receivedT[0]),
        str(Decimal(predT)),
        str(Decimal(handT)))
        mycursor.execute(insert_query.replace('name', name), info)
        logger.info("Record inserted successfully into " + name + " table")
        mydb.commit()
    except mysql.connector.Error as error:
        mydb.rollback()
        logger.error("An error occurred while inserting a flow: "+ str(error))
    except Exception as error:
        logger.error("Exception occurred", exc_info=True)
    finally:
        if mydb.is_connected():
            mycursor.close()
            mydb.close()
            logger.info("Connection is closed")

'''
    get all flows from selected db
'''
def getFlows(name):
    db, cursor = getdb_cursor()
    select_query = """
    SELECT * FROM name;
    """
    logger = utils.getLogger()
    try:
        cursor.execute(select_query.replace('name', name))
    except mysql.connector.Error as error:
        db.rollback()
        logger.error("An error occurred while getting the flows from {}: ".format(name)+ error)
        return None
    except Exception as e:
        logger.error("Exception occurred", exc_info=True)
        print(e)
        return None
    finally:
        a = cursor.fetchall()
        if db.is_connected():
            cursor.close()
            db.close()
            logger.info("Connection is closed")
        return a

'''
    get all blockedIp addresses
'''
def getBlockedIp():
    de, cursor = getdb_cursor()
    select_query = '''
    SELECT * FROM blockedIp;
    '''
    logger = utils.getLogger()
    try:
        cursor.execute(select_query)
    except mysql.connector.Error as error:
        db.rollback()
        logger.error("An error occurred while getting the blocked IPs: " + error)
        return None
    except Exception as e:
        logger.error("Exception occurred", exc_info=True)
        print(e)
        return None
    finally:
        if db.is_connected():
            cursor.close()
            db.close()
            logger.info("Connection is closed")
        return cursor.fetchall()


'''
    get only the columns with a certain flow_id for the flow db
'''
def getFlowIdFCols(name, cols, flowId, receivedT):
    global slot_interval
    db, cursor = getdb_cursor()
    select_query = """
    SELECT cols FROM name WHERE Flow_ID = \'flowid\' AND ABS(Received_Time-received)<=slot_interval;
    """
    a = None
    logger = utils.getLogger()
    try:
        c = ''
        for i in range(len(cols)):
            if i + 1 != len(cols):
                c += str(cols[i]) + ', '
            else:
                c += str(cols[i])

        cursor.execute(select_query.replace('name', name).replace('slot_interval', str(slot_interval)).replace('cols', c).replace('flowid', flowId).replace('received', str(receivedT)))
        a = cursor.fetchall()
    except mysql.connector.Error as error:
        db.rollback()
        logger.error("An error occurred while getting the flows from {}: ".format(name)+ error)
        return []
    except Exception as e:
        logger.error("Exception occurred", exc_info=True)
        print(e)
        return []
    finally:
        if db.is_connected():
            cursor.close()
            db.close()
            logger.info("Connection is closed")
        if a != None:
            return a
        return []

'''
    get only the columns with a certain flow_id for the packet db in a time range
'''
def getFlowIdPCols(name, cols, flowId, receivedT):
    global slot_interval
    db, cursor = getdb_cursor()
    select_query = """
    SELECT cols FROM name WHERE Flow_ID = \'flowid\' AND ABS(Received_Time-received)<=slot_interval;
    """
    logger = utils.getLogger()
    a = None
    try:
        c = ''
        for i in range(len(cols)):
            if i + 1 != len(cols):
                c += str(cols[i]) + ', '
            else:
                c += str(cols[i])

        cursor.execute(select_query.replace('name', name).replace('slot_interval',str(slot_interval)).replace('cols', c).replace('flowid', flowId).replace('received',str(receivedT)))
        a = cursor.fetchall()
    except mysql.connector.Error as error:
        db.rollback()
        logger.error("An error occurred while getting the packets from {}: ".format(name)+ error)
        return []
    except Exception as e:
        logger.error("Exception occurred", exc_info=True)
        print(e)
        return []
    finally:
        if db.is_connected():
            cursor.close()
            db.close()
            logger.info("Connection is closed")
        if a != None:
            return a
        return []


'''
    get only the columns necessary for the flow db
'''
def getSomeFlowCols(name, cols):
    db, cursor = getdb_cursor()
    select_query = """
    SELECT cols FROM name;
    """
    logger = utils.getLogger()
    try:
        c = ''
        for i in range(len(cols)):
            if i + 1 != len(cols):
                c += str(cols[i]) + ', '
            else:
                c += str(cols[i])

        cursor.execute(select_query.replace('name', name).replace('cols', c))
    except mysql.connector.Error as error:
        db.rollback()
        logger.error("An error occurred while getting the flows from {}: ".format(name)+ error)
        return None
    except Exception as e:
        logger.error("Exception occurred", exc_info=True)
        print(e)
        return None
    finally:
        if db.is_connected():
            cursor.close()
            db.close()
            logger.info("Connection is closed")
        return cursor.fetchall()

'''
    get only the columns necessary for the packets db
'''
def getSomePacketsCols(name, cols):
    db, cursor = getdb_cursor()
    select_query = """
    SELECT cols FROM name;
    """
    logger = utils.getLogger()
    try:
        c = ''
        for i in range(len(cols)):
            if i + 1 != len(cols):
                c += str(cols[i]) + ', '
            else:
                c += str(cols[i])

        cursor.execute(select_query.replace('name', name).replace('cols', c))
    except mysql.connector.Error as error:
        db.rollback()
        logger.error("An error occurred while getting the packets from {}: ".format(name)+ error)
        return None
    except Exception as e:
        logger.error("Exception occurred", exc_info=True)
        print(e)
        return None
    finally:
        if db.is_connected():
            cursor.close()
            db.close()
            logger.info("Connection is closed")
        return cursor.fetchall()

'''
    Here is checked the number of hits received in a slot interval by the same
    address that is currently analyzed
    get the number of packets that passed until now with the same flowId
    in a set slot interval
    set slot_interval = 2 second
'''
def getCountSamePackets(flowid, receivedT, data, slot_interval = 2):
    if type(data) != type(None):
        sum = len(data[(abs(data['Packets/Time'] - receivedT) <= slot_interval) & (utils.getFlowId(data['Source IP'], data['Dest IP'], data['Source Port'], data['Dest Port'], '4') == flowid)])
        print(sum)
        exit()
        return [sum]
    else:
        logger = utils.getLogger()
        db, cursor = getdb_cursor()
        sum = 0
        select_query = '''
        SELECT COUNT(*)
        FROM name
        WHERE Flow_ID = \'flowid\' AND ABS(Received_Time-received)<=slot_interval
        '''
        select_query = select_query.replace('flowid', str(flowid)).replace('received', str(receivedT)).replace('slot_interval', str(slot_interval))
        try:
            cursor.execute(select_query.replace('name', 'finalPackets'))
            rows = cursor.fetchone()
            sum += rows[0]
            cursor.execute(select_query.replace('name', 'newPackets0'))
            rows = cursor.fetchone()
            sum += rows[0]
            cursor.execute(select_query.replace('name', 'newPackets1'))
            rows = cursor.fetchone()
            sum += rows[0]
            cursor.execute(select_query.replace('name', 'newPackets2'))
            rows = cursor.fetchone()
            sum += rows[0]
            logger.info("Managed to record the presence counts for "+ str(flowid))
        except mysql.connector.Error as error:
            db.rollback()
            print(e)
            logger.error("An error occurred while getting the count from {}: ".format(name)+ error)
            return [sum]
        except Exception as e:
            logger.error("Exception occurred", exc_info=True)
            print(e)
            return [sum]
        finally:
            if db.is_connected():
                cursor.close()
                db.close()
                logger.info("Connection is closed")
            return [sum]


'''
    get all packets from selected db
'''
def getPackets(name):
    db, cursor = getdb_cursor()
    select_query = """
    SELECT * FROM name;
    """
    logger = utils.getLogger()
    try:
        cursor.execute(select_query.replace('name', name))
    except mysql.connector.Error as error:
        db.rollback()
        logger.error("An error occurred while getting the packets from {}: ".format(name)+ error)
        return None
    except Exception as e:
        logger.error("Exception occurred", exc_info=True)
        print(e)
        return None
    finally:
        if db.is_connected():
            cursor.close()
            db.close()
            logger.info("Connection is closed")
        return cursor.fetchall()
