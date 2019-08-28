import netifaces
import pyshark
import os
import csv
import multiprocessing
import pandas as pd
import subprocess
from scipy.io import arff
import threading
import time
import random
import logging
import mysql.connector
from shutil import copyfile, rmtree
from sklearn.model_selection import train_test_split
from keras import utils as U
import tensorflow as tf
from tensorflow import keras
import MLP
import Utils as utils
import RetrainModels as rtm
import DbSetUp as dtb
import datetime
import numpy
import matplotlib.pyplot as plt
import BlockIps as bl
from pymouse import PyMouse
from datetime import date
from collections import Counter

logging._warn_preinit_stderr = 0
logging.basicConfig(filename='log/app.log', filemode='w+', format='%(process)d - %(thread)s - %(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

utils.setLogger(logger)

#root directory
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

#false positive Counter
falsePackets = 0
falseFlows = 0

#decisions Counter
flowsT = 0
flowsA = 0
packA = 0
packT = 0

#databases indicators
flowWorkingDb = 1
trafficWorkingDb = 1
#those correspond to packet model
trainingTimeout = 360
fullTrainingTimeout = 7200
#those correspond to flow models
fullFTrainingTimeout = 100000
trainingFTimeout = 3600

start = check = end = time.time()

startF = checkF = endF = time.time()

numeric_types = [int, float, complex]

modelFlow = MLP.MLP([100,100], 147)
modelPacket = MLP.MLP([10,10], 8, optimizer='rms')

trainingLock = threading.Lock()
flowLock = threading.Lock()

config = tf.ConfigProto(
    device_count={'GPU': 1},
    intra_op_parallelism_threads=1,
    allow_soft_placement=True
)

config.gpu_options.allow_growth = True
config.gpu_options.per_process_gpu_memory_fraction = 0.6

session = tf.Session(config=config)

keras.backend.set_session(session)

'''
    Get the highest_layer, transport_layer, source_Ip, destination_Ip,
    Source_Port, Destination_Port, Packet_length, Packet/Time information
    about a packet
'''
def get_packet_information(packet, time, count):
    global logger
    try:
        if packet.highest_layer != 'ARP':
            ip= utils.get_ip(packet)
            packets_time = 0
            if float(time) != 0:
                packets_time = count / float(time)
            try:
                #'Source Port', 'Dest Port', 'Source IP', 'Dest IP', 'Packet Length','Packets/Time', 'Packet Type',
                data = [ip.src, ip.dst, int(packet[packet.transport_layer].srcport),
                        int(packet[packet.transport_layer].dstport), int(packet.length),
                        packets_time, packet.highest_layer, packet.transport_layer]
                return data
            except AttributeError:
                data = [ip.src, ip.dst, 0, 0, int(packet.length), packets_time,
                        packet.highest_layer, packet.transport_layer]
                return data
    except (UnboundLocalError, AttributeError):
        ip= utils.get_ip(packet)
        if ip is None:
            logger.info("The packet "+ str(count) + " wasn't identified as either IPv4 or IPv6\n")
            logger.info(packet)
        else:
            logger.info("An unknown error has occurred with packet "+ str(count) +"\n")
            logger.info(packet)
        return None


'''
    Handle the threatening attack by blocking the source of the traffic
'''
def handleDDoS(ip, flowip, port, origin):

    utils.blockIp(ip, flowip, port, origin)


'''
    Check whether the packet is dangerous or not by computing the prediction
    that it is a ddos attack or not
    packet- packet to be analyzed
    count- the count of the packet that was reached
    timeRecorded - the time at which the packet was Recorded
    arriveT - time at which the packet actually arrived at
    db - the currently used db
'''
def check_packet(packet, count, timeRecorded, arriveT, db):
    global modelPacket, logger, falsePackets, session, packT, packA
    packT += 1
    try:

        datat = get_packet_information(packet, arriveT, count)
        if datat == None:
            pass
        else:
            protocol = utils.get_ipvx(packet)

            data, nonNumeric = utils.labelEncoder(datat, 'LiveCapture')
            data = pd.DataFrame(data, columns=utils.getPacketNames())
            flowId = utils.getFlowId(nonNumeric[1], nonNumeric[0], int(data['Dest Port']), int(data['Source Port']), protocol)
            #once done remove the first and uncomment the second
            #prediction = 0
            try:
                with session.as_default():
                    with session.graph.as_default():
                        modelPacket.model._make_predict_function()
                        prediction = modelPacket.model.predict(data)
                        prediction = numpy.argmax(prediction[0])
                        packA += prediction
                        print()
                        print("This is packet "+ str(datat) )
                        print("This is prediction " + str(prediction))
                        print("Recorded "+ str(packT) +" packs ")
                        print("From those "+ str(packA) + " were attacks")
                        print()
                        predictedTime = time.time() - timeRecorded

                        #check the percentage that this packet is part of an attack
                        flows = pd.DataFrame()

                        aux = dtb.getFlowIdFCols('finalFlow',['Flow_ID','Label'],flowId,arriveT)
                        if aux != []:
                            flows = flows.append(aux, ignore_index=True)
                        aux = dtb.getFlowIdFCols('newFlow0',['Flow_ID','Label'],flowId,arriveT)
                        if aux != []:
                            flows = flows.append(aux, ignore_index=True)
                        aux = dtb.getFlowIdFCols('newFlow1',['Flow_ID','Label'],flowId,arriveT)
                        if aux != []:
                            flows = flows.append(aux, ignore_index=True)
                        aux = dtb.getFlowIdFCols('newFlow2',['Flow_ID','Label'],flowId,arriveT)
                        if aux != []:
                            flows = flows.append(aux, ignore_index=True)

                        packets = pd.DataFrame()

                        aux = dtb.getFlowIdPCols('finalPackets',['Flow_ID', 'Predict'],flowId,arriveT)
                        if aux != []:
                            packets = packets.append(aux, ignore_index = True)
                        aux = dtb.getFlowIdPCols(db,['Flow_ID', 'Predict'],flowId,arriveT)
                        if aux != []:
                            packets = packets.append(aux, ignore_index = True)

                        pred = 0
                        if flows.empty and packets.empty:
                            pred = prediction
                        else:
                            packets = packets.append(pd.DataFrame([[flowId,prediction]]), ignore_index = True)
                            if not flows.empty:
                                flows.columns = ['Flow_ID', 'Label']
                            else:
                                flows = pd.DataFrame(columns = ['Flow_ID', 'Label'])
                            if not packets.empty:
                                packets.columns =  ['Flow_ID', 'Predict']
                            else:
                                packets = pd.DataFrame(columns = ['Flow_ID', 'Predict'])

                            pred = utils.getTargets(packets, flows)[0]

                        if pred != prediction:
                            logger.info("Found a possible false positive in packets check")
                            falsePackets += 1

                        if pred == 0 :
                            print("Packet Not attack")
                            print()
                            print()
                            insert = threading.Thread(name="check_packet"+str(count), target = dtb.insert_packet, args=(data, nonNumeric, protocol, prediction, arriveT, predictedTime, predictedTime, db))
                            insert.start()
                            insert.join()
                        elif pred == 1:
                            print("Packet Attack")
                            print()
                            print()
                            handleAttack = threading.Thread(target = handleDDoS, args=(nonNumeric[1], flowId,data['Source Port'], 'Packet'), daemon=True)
                            handleAttack.start()
                            handleAttack.join()
                            handledTime = time.time() - timeRecorded
                            insert = threading.Thread(name="check_packet"+str(count), target = dtb.insert_packet, args=(data, nonNumeric, protocol, prediction, arriveT, predictedTime, handledTime, db))
                            insert.start()
                            insert.join()
                        else:
                            logger.warning("There is an unexpected prediction answer "+ str(prediction))
            except Exception as e:
                logging.error(e)
    except KeyboardInterrupt as e :
        global logger
        logger.info("Program interrupted")
        return


'''
    There exists an issue with the CICFlowMeter's conversion from captured packets
    to flows; as such, only the live recording of flows is allowed (as this is not
    a main part of the topic it is not to be dealt with)
'''
def check_flow(time, count):
    global logger
    logger.info("Flow is checked somewhere else")


'''
    This function checks when a training was ended so that the used model can change
'''
def changeUsedPacketModel():
    global logger
    try:
        training = False
        global trainingLock, modelPacket
        while(True):
            if trainingLock.locked():
                training = True
            elif training == True:
                modelPacket.model.load_weights('trafficModels/currentModel.h5')
                print("Model was changed")
                training = False
            else:
                pass
    except KeyboardInterrupt as e:
        print("Program was stopped")
        return
    except Exception as e:
        logger.error("Exception occurred", exc_info=True)

'''
    this function checks if it is the time for one of the packet db to be trained
    by checking if there exists any other training currently in progress and if
    the time for training was reached.
'''
def checkTrainingTimesP(count):
    global start, check, end, logger, fullTrainingTimeout, ROOT_DIR, trainingLock, trainingTimeout, trafficWorkingDb
    if end - start >= fullTrainingTimeout:
        start = check = time.time()
        nameTraining = ''
        #stop any active refiting
        for t in multiprocessing.active_children():
            if t.name in ['TrainingPacket1', 'TrainingPacket2', 'TrainingPacket0']:
                nameTraining = str(t.name).replace('TrainingPacket','newPackets')
                t.stop()
                t.join()
                #try to remove the epoch folders
                if os.path.exists(ROOT_DIR + "/filePacketTrained"):
                    try:
                        rmtree(ROOT_DIR + "/filePacketTrained")
                    except OSError as e:
                        print ("Error: %s - %s." % (e.filename, e.strerror))
                dtb.insertPTable(nameTraining)
        logger.info("Fully retrain at count "+ str(count))
        print(count)
        #move all existent data in the main db
        dtb.insertPTable('newPackets'+str(trafficWorkingDb))
        fullTraining = rtm.retrainPacketModel(args=('finalPackets', trainingLock),
            name="finalPacketsTraining", daemon=True)
        logger.info("Started training a completely new model for checking packets")
        fullTraining.start()
        #use a new db for storing
        trafficWorkingDb = (trafficWorkingDb + 1) % 3
        logger.info("Changed to new packet database "+ str(trafficWorkingDb))

    #if the training time is reached, check if no training is occuring
    #if another training is occuring, keep on storing information
    elif end - check >= trainingTimeout:
        check = time.time()
        logger.info("Finished working with packet "+ str(trafficWorkingDb))
        #check if any database is in training
        #change working database to the nontraining one
        changedProcess = False
        for t in multiprocessing.active_children():
            if t.name == 'finalPacketsTraining':
                logger.info("Currently a completely new packet model is being trained")
                trafficWorkingDb = (trafficWorkingDb + 1) % 3
                changedProcess = True
                break
            elif t.name not in ['TrainingPacket0', 'TrainingPacket1', 'TrainingPacket2']:
                pass
            elif t.name == ("TrainingPacket" + str((trafficWorkingDb + 1) % 3)):
                trafficWorkingDb = (trafficWorkingDb + 2) % 3
                changedProcess = True
                break
            elif t.name == ("TrainingPacket" + str((trafficWorkingDb + 2) % 3)):
                trafficWorkingDb = (trafficWorkingDb + 1) % 3
                changedProcess = True
                break
            elif t.name == ("TrainingPacket" + str(trafficWorkingDb)) :
                logger.error("Error: Program has been writing in the training packet database")
                trafficWorkingDb = (trafficWorkingDb + 1) % 3
                changedProcess = True
                break
            else:
                pass

        #if no database is training refit the current one
        if changedProcess == False:
            logger.info("Partial retraining at count "+ str(count))
            print("Partial at "+ str(count))
            nameProcess = "TrainingPacket" + str(trafficWorkingDb)
            if os.path.exists(ROOT_DIR + "/filePacketTrained"):
                try:
                    rmtree(ROOT_DIR + "/filePacketTrained")
                except OSError as e:
                    print ("Error: %s - %s." % (e.filename, e.strerror))
            training = rtm.retrainPacketModel(args=('newPackets'+str(trafficWorkingDb), trainingLock),
                name=nameProcess, daemon=True)
            logger.info("Started training packet "+ str(trafficWorkingDb))
            training.start()
            trafficWorkingDb = (trafficWorkingDb + 1) % 3
        logger.info("Changed to new packet database "+ str(trafficWorkingDb))
    return

'''
    capture live-traffic from selected interface into the respective
    thread pcap file
    The function then passes the packet onto a checker and onto a time checker, meant to
    determine if the time for refitting or retraining was reached
'''
def capture_interface(iface):
    global trafficWorkingDb, logger, start, check, end, falseFlows, falsePackets
    #save all traffic for checking for false positives and missed values
    if iface == "all":
        cap = pyshark.LiveCapture(output_file="traffic.pcap")
    else:
        cap = pyshark.LiveCapture(interface=iface, output_file="traffic.pcap")
    cap.set_debug()
    packet_iterator = cap.sniff_continuously

    changeUsedModel = threading.Thread(name="changeUsedPacketModel", target=changeUsedPacketModel, args=())
    changeUsedModel.start()

    try:
        start = check = time.time()
        count = 0
        #for each read packet
        for packet in packet_iterator():
            count += 1
            end = time.time()
            #check if packet is a threat
            arriveT = packet.frame_info.time_relative
            check_packet(packet, count, end, arriveT, 'newPackets' + str(trafficWorkingDb))

            #check if it is time for retraining
            training = threading.Thread(name = "checkTrainingTimesP", target= checkTrainingTimesP, args=(count,))
            training.start()

    except Exception as e:
        print(e)
    except KeyboardInterrupt:
        print("The number of false packets were "+ str(falsePackets))
        print("The number of false flows were "+ str(falseFlows))
        utils.closeVers()
        cap.close()
        time.sleep(1)
        main_thread = threading.currentThread()
        for t in threading.enumerate():
            if t is main_thread:
                pass
            t.join()
        for t in multiprocessing.active_children():
            t.stop()
            t.join()
        exit()
    #get_flow_spec()
    cap.close()

'''
    this function checks if a new model was created and changes the current used one to that one
'''
def changeUsedFlowModel():
    global logger
    try:
        training = False
        global flowLock, modelFlow
        while(True):
            if flowLock.locked():
                training = True
            elif training == True:
                modelFlow.model.load_weights('flowModels/currentModel.h5')
                print("Model was changed")
                training = False
            else:
                pass
    except KeyboardInterrupt as e :
        print("Program was stopped")
        return
    except Exception as e:
        logger.error("Exception occurred", exc_info=True)


'''
    this function checks if it is the time for one of the flow db to be trained
    by checking whether there is another training in execution and by checking that
    the training time was reached
    count - marks the number of flows reached
'''
def checkTrainingTimesF(count):
    global startF, checkF, endF, fullFTrainingTimeout, logger, ROOT_DIR, trainingFTimeout, flowWorkingDb, flowLock
    if endF - startF >= fullFTrainingTimeout:
        startF = checkF = time.time()
        nameTraining =''
        #stop any refitting
        for r in multiprocessing.active_children():
            if t.name in ['TrainingFlow1','TrainingFlow2','TrainingFlow0']:
                nameTraining = str(t.name).replace("TrainingFlow", 'newFlow')
                t.stop()
                t.join()
                #Try to remove epoch folders
                if os.path.exists(ROOT_DIR + "/fileFlowTrained"):
                    try:
                        rmtree(ROOT_DIR + 'filePacketTrained')
                    except OSError as e:
                        print ("Error: %s - %s." %(e.filename, e.strerror))
                dtb.insertFTable(nameTraining)
        logger.info("Fully retrain at count" + str(count))
        print(count)
        #move all existent data in the main db
        dtb.insertFTable('newFlow' + str(flowWorkingDb))
        fullTraining = rtm.retrainFlowModel(args=('finalFlow',flowLock), name ='finalFlowsTraining', daemon=True)
        logger.info("Started training a completely new model for checking flows")
        fullTraining.start()
        #change db for storing
        flowWorkingDb = (flowWorkingDb + 1) % 3
        logger.info("Changed to new flow database" + str(flowWorkingDb))
    #if the training time is reached check if no othr training is ocurring
    #if another is happening , keep on storing information
    elif endF - checkF >= trainingFTimeout:
        checkF = time.time()
        logger.info("Fininshed working with flow "+ str(flowWorkingDb))
        #check if any db in trainingFile
        #change working db to nontraining one
        changedProcess = False
        for t in multiprocessing.active_children():
            if t.name == 'finalFlowsTraining':
                logger.info("Currently a completely new flow model is being trained")
                flowWorkingDb = (flowWorkingDb + 1) % 3
                changedProcess = True
                break
            elif t.name not in ['TrainingFlow0', 'TrainingFlow1', 'TrainingFlow2']:
                pass
            elif t.name == ("TrainingFlow" + str((flowWorkingDb + 1) % 3)):
                flowWorkingDb = (flowWorkingDb + 2) % 3
                changedProcess = True
                break
            elif t.name == ("TrainingFlow" + str((flowWorkingDb + 2) % 3)):
                flowWorkingDb = (flowWorkingDb + 1) % 3
                changedProcess = True
                break
            elif t.name == ("TrainingFlow" + str(flowWorkingDb)) :
                logger.error("Error: Program has been writing in the training packet database")
                flowWorkingDb = (flowWorkingDb + 1) % 3
                changedProcess = True
                break
            else:
                pass

        #if no database is in training refit the current one
        if changedProcess == False:
            logger.info("Partial retraining at count "+ str(count))
            print("Partial at "+ str(count))
            nameProcess = "Training Flow" + str(flowWorkingDb)
            if os.path.exists(ROOT_DIR + "/fileFlowTrained"):
                try:
                    rmtree(ROOT_DIR + "/fileFlowTrained")
                except OSError as e:
                    print ("Error: %s - %s." % (e.filename, e.strerror))
            training = rtm.retrainFlowModel(args=('newFlow'+str(trafficWorkingDb), trainingLock),
                name=nameProcess, daemon=True)
            logger.info("Started training packet "+ str(trafficWorkingDb))
            training.start()
            flowWorkingDb = (flowWorkingDb + 1) % 3
        logger.info("Changed to new packet database "+ str(trafficWorkingDb))

'''
    flow- flow to be analyzed
    timeRecorded - the time the flow was read as
    arriveT - the time the flow was recorded (not started to analyze) at
    db - the currently used db
    count- the flow reached to analyze
    The function obtains the converted data and it tests it against a predictive
    model. If traffic is attack then the flow gets sent to mitigation and then
    gets saved
    otherwise, it gets saved
'''
def flowCheck(flow, timeRecorded, arriveT, db, count):
    global modelFlow, logger, session, falseFlows, flowsT, flowsA
    flowsT += 1
    try:

        remove = ["Src IP", "Dst IP", "Label\n", "Timestamp", "Flow ID"]
        df = utils.to_one_hot_encoding(flow).drop(remove, axis=1)

        dat = df.drop(['Flow Byts/s', 'Flow Pkts/s'], axis=1)
        df_num = dat.apply(pd.to_numeric)
        df_num = df_num.select_dtypes(['number'])
        dataset = df_num.to_numpy()
        prediction = 0
        #session.run(tf.global_variables_initializer())
        try:
            with session.as_default():
                with session.graph.as_default():
                    modelFlow.model._make_predict_function()
                    prediction = modelFlow.model.predict(dataset)
                    prediction = numpy.argmax(prediction[0])
                    flowsA += prediction
                    print("Recorded "+ str(flowsT) +" flows ")
                    print("From those "+ str(flowsA) + " were attacks")
                    print()
                    print("This is flow check")
                    print(flow)
                    print("The prediction is: "+ str(prediction))
                    print()
                    predictedTime = time.time() - timeRecorded

                    flowId = flow['Flow ID']
                    #check if overall this flow belongs to an attack
                    flows = pd.DataFrame()

                    aux = dtb.getFlowIdFCols(db,['Flow_ID','Label'],flowId[0],arriveT)
                    if aux != []:
                        flows = flows.append(aux, ignore_index=True)
                    aux = dtb.getFlowIdFCols('finalFlow',['Flow_ID','Label'],flowId[0],arriveT)
                    if aux != []:
                        flows = flows.append(aux, ignore_index=True)

                    packets = pd.DataFrame()

                    aux = dtb.getFlowIdPCols('finalPackets',['Flow_ID', 'Predict'],flowId[0],arriveT)
                    if aux != []:
                        packets = packets.append(aux, ignore_index = True)
                    aux = dtb.getFlowIdPCols('newPackets0',['Flow_ID', 'Predict'],flowId[0],arriveT)
                    if aux != []:
                        packets = packets.append(aux, ignore_index = True)
                    aux = dtb.getFlowIdPCols('newPackets1',['Flow_ID', 'Predict'],flowId[0],arriveT)
                    if aux != []:
                        packets = packets.append(aux, ignore_index = True)
                    aux = dtb.getFlowIdPCols('newPackets2',['Flow_ID', 'Predict'],flowId[0],arriveT)
                    if aux != []:
                        packets = packets.append(aux, ignore_index = True)

                    pred = 0
                    if flows.empty and packets.empty:
                        pred = prediction
                    else:
                        flows = flows.append(pd.DataFrame([[flow['Flow ID'], prediction]]), ignore_index = True)

                        if not flows.empty:
                            flows.columns = ['Flow_ID', 'Label']
                        else:
                            flows = pd.DataFrame(columns = ['Flow_ID', 'Label'])
                        if not packets.empty:
                            packets.columns =  ['Flow_ID', 'Predict']
                        else:
                            packets = pd.DataFrame(columns = ['Flow_ID', 'Predict'])


                        pred = utils.getTargetsF(flows, packets)[0]

                    if pred != prediction:
                        logger.info("Found a possible false positive in flows check")
                        falseFlows += 1

                    if pred == 0 :
                        print("Flow Not attack")
                        print()
                        print()
                        insert = threading.Thread(name="check_Flow"+str(count), target = dtb.insertFlow, args=(flow.drop('Label\n', axis=1), prediction, arriveT, predictedTime, predictedTime, db))
                        insert.start()
                        insert.join()
                    elif pred == 1:
                        print("Flow Attack")
                        print()
                        print()
                        handleAttack = threading.Thread(target = handleDDoS, args=(str(flow['Src IP']),str(flow['Flow ID']),int(flow['Src Port']),'Flow'), daemon=True)
                        handleAttack.start()
                        handleAttack.join()
                        handledTime = time.time() - timeRecorded
                        insert = threading.Thread(name="check_Flow"+str(count), target = dtb.insertFlow, args=(flow.drop('Label\n', axis=1), prediction, arriveT, predictedTime, handledTime, db))
                        insert.start()
                        insert.join()
                    else:
                        logger.warning("There is an unexpected prediction answer "+ str(prediction))
        except Exception as e:
            print(e)
    except KeyboardInterrupt as e :
        global logger
        logger.info("Program interrupted")
        return


def follow(thefile):
    thefile.seek(0,2)
    while True:
        line = thefile.readline()
        if not line:
            #time.sleep(0.1)
            continue
        yield line


'''
    count- the number of flow that we have reached to read (starts from 0)
    the function reads flows as they get saved inside the daily flow.csv file,
    which then get sent for checking and for retraining if necessary
'''
def watch_flow(count):
    global flowWorkingDb, startF, endF, checkF, logger, flowsT, flowsA, packA, packT
    day = date.today()
    flowPacketName = "data/daily/" + str(day) + "_Flow.csv"

    changeUsedModel = threading.Thread(name="changeUsedFlowModel", target=changeUsedFlowModel, args=())
    changeUsedModel.start()

    try:
        logfile = open(flowPacketName, "r")
        cols = logfile.readline()
        utils.setFlowNames(cols.split(","))
        loglines = follow(logfile)
        startF = checkF = time.time()
        lines = logfile.readlines()
        #for line in loglines:
        while True:
            lines = logfile.readlines()
            #print(lines)
            #line = logfile.readline()
            for line in lines:
                count += 1
                endF = time.time()
                flow = pd.DataFrame([line.split(",")], columns = utils.getFlowNames())
                print(flow)
                arriveT = flow['Timestamp']
                #check if flow is a threat
                flowCheck(flow, endF, arriveT, 'newFlow' + str(flowWorkingDb), count)

                training = threading.Thread(name="checkTrainingTimesF", target=checkTrainingTimesF, args=(count,))
                training.start()
    except KeyboardInterrupt:
        return
    except Exception as e:
        print(e)
        time.sleep(2)
        watch_flow(count)



'''
    Starts 1/3 CICFlowMeter instances
    This is necessary as some error in the programatic side of the app used only allows
    for a correct reading to be done in live reading
    In case the application doesn't single-handledly start the reading of traffic on
    any, then that needs to be started by hand.
'''
def run_CICFlowMeter():
    m = PyMouse()
    x, y = m.position()
    cmd = ['sudo ./CICFlowMeter']
    #open 3 app instances
    p = subprocess.Popen(cmd,shell=True, stdout=subprocess.PIPE)
    #p = subprocess.Popen(cmd,shell=True, stdout=subprocess.PIPE)
    #p = subprocess.Popen(cmd,shell=True, stdout=subprocess.PIPE)
    #separate the instances on the screen
    time.sleep(5)
    m.press(650,300,1) #move 1
    m.release(60,20)
    time.sleep(0.5)
    m.move(740,300)
    time.sleep(0.5)
    '''m.press(740,300,1) #move 2
    m.release(100,500)
    m.move(750,300)
    time.sleep(0.5)
    m.press(750,300,1) #move 3
    m.release(800,20)
    time.sleep(0.5)'''
    m.click(60,370) #set load1
    time.sleep(2)
    '''m.click(750,370) #set load2
    time.sleep(0.5)
    m.click(60,850) #set load3
    time.sleep(0.5)'''
    m.click(300,490)
    m.click(300,480) #set any
    time.sleep(0.25)
    '''m.click(790,490)
    time.sleep(0.25)
    m.click(790,480) #set any
    time.sleep(0.25)
    m.click(300,870)
    time.sleep(0.25)
    m.click(300,960) #set any
    time.sleep(0.25)'''
    s = time.time()
    m.click(60,410) #start 1
    time.sleep(0.25)
    '''m.click(740,400) #start 2
    time.sleep(0.5)
    m.click(30,878) #start 3'''

    '''inst1 = threading.Thread(target = run1, args=(m,s))
    inst2 = threading.Thread(target = run2, args=(m,s))
    inst3 = threading.Thread(target = run3, args=(m,s))'''

    '''inst1.start()
    inst2.start()
    inst3.start()'''

    p.wait()

'''
    choose an interface
    and then capture the traffic and the respective flow
    any to sniff all interfaces
    timeout- capture time
'''
def read_and_analize_traffic():
    print(-1, "any ")
    interfaces = utils.interface_names()
    for i, value in enumerate(interfaces):
        print(i, value)
    print('\n')
    iface = input("Please select interface by name: ")
    flowReader = threading.Thread(target=run_CICFlowMeter, args=())
    flowReader.start()
    packet = threading.Thread(target=capture_interface, args=(iface,))
    flow = threading.Thread(target=watch_flow, args=(0,))
    packet.start()
    flow.start()
    packet.join()
    flow.join()

'''
    run 3 stops the 1st instance every 180 seconds and saves the recorded flows
    m - mouse controller
    t - current time
'''
def run3(m, t):
    try:
        pas = False
        while pas == False:
            e = time.time()
            if e - t >= 180:
                m.click(30,920) #stop 3
                time.sleep(0.5)
                m.click(30,920)
                time.sleep(0.5)
                m.click(400,780) #save in time 3
                time.sleep(0.25)
                m.click(30,878) #start 3
                t = e
                pas = True
        run3(m, t)
    except KeyboardInterrupt as e:
        return

'''
    run 2 stops the 1st instance every 120 seconds and saves the recorded flows
    m - mouse controller
    t - current time
'''
def run2(m, t):
    try:
        pas = False
        while pas == False:
            e = time.time()
            if e - t >= 120:
                m.click(750,450) #stop 2
                time.sleep(0.25)
                m.click(750,450)
                time.sleep(0.5)
                m.click(990,310) #save in time 2
                time.sleep(0.25)
                m.click(740,400) #start 2
                t = e
                pas = True
        run2(m, t)
    except KeyboardInterrupt as e:
        return

'''
    run 1 stops the 1st instance every 60 seconds and saves the recorded flows
    m - mouse controller
    t - current time
'''
def run1(m, t):
    try:
        pas = False
        while pas == False:
            e = time.time()
            if e - t >= 60:
                m.click(60,450) #stop 1
                time.sleep(0.25)
                m.click(60,450)
                time.sleep(0.5)
                m.click(390,310) #save in time 1
                time.sleep(0.25)
                m.click(60,400) #start 1
                t = e
                pas = True
        run1(m, t)
    except KeyboardInterrupt as e:
        return



'''
    Lets you choose a model out of the existent ones to become
    the currently used one
'''
def choose_model(models, name):
    print("Choose model to be used as the current model for "+ name)
    for i in range(0,len(models)):
        print(str(i+1)+ ". " + str(models[i]))
    modelInd = input("\nWhich model (index)?\n")
    if int(modelInd)-1 in range(0,len(models)):
        return str(models[int(modelInd)-1])
    else:
        print("Choose an index\n")
        choose_model(models, name)

'''
    model - model to be retrained
    data - data used for retraining
    THis function completely retrains a model from a data file
'''
def retrain_model(model, data):
    global session, logger
    encodedData = []
    targetsF = []
    if 'Time to Live' in data:
        target= pd.DataFrame(data[['target']].applymap(lambda x: utils.get_Target(x)))
        targetsF = U.to_categorical(target, num_classes=2)
        print(data.columns)
        keep = ['Source IP', 'Dest IP', 'Source Port', 'Dest Port', 'Byte Size', 'Packet Length', 'Time to Live', 'Packets/Time']
        encodedData = data[keep]
        encodedData['Packet Type'] = data[['Packet Type']].applymap(lambda x: utils.get_Type_Coding(x))
        print(encodedData.columns)
        exit()
        try:
            retrainingInfo = train_test_split(encodedData, targetsF, test_size=0.2, random_state=42)
            model.load_data(retrainingInfo.copy())
            print("loaded")
            session.run(tf.initialize_all_variables())
            stats = model.train(20, 6, 9, 'filePacketTrained', patience=50)
            print("trained")
            try:
                with session.as_default():
                    with session.graph.as_default():
                        score = model.evaluate()

                        model.save_model('trafficModels')
                        print('Test loss: ' + str(round(score[0], 3)))
                        print('Test accuracy ' + str(round(score[1], 3)) + " (+/-" + str(numpy.std(round(score[1], 3))) + ")")
                        plt.plot(stats['train_loss'])
                        plt.plot(stats['val_loss'])
                        plt.title('model loss')
                        plt.xlabel('epoch')
                        plt.ylabel('loss')
                        plt.legend(['train', 'test'], loc='upper left')
                        plt.show()
                        print(stats)
            except Exception as ex:
                logger.log('Error s ', ex, ex.__traceback__.tb_lineno)
        except Exception as e:
            logger.error("Exception occurred", exc_info=True)
    else:
        encodedData = pd.DataFrame(columns=utils.getPacketNames())
        encodedData = data.apply(lambda x: utils.labelEncoder(x, 'Training')[0], axis=1)
        encodedData.columns = utils.getPacketNames()
        targets = data['target']
        targetsF = U.to_categorical(targets.copy(), num_classes=2)
        try:
            retrainingInfo = train_test_split(encodedData, targetsF, test_size=0.2, random_state=42)
            model.load_data(retrainingInfo.copy())
            print("loaded")
            session.run(tf.initialize_all_variables())
            stats = model.train(20, 6, 8, 'filePacketTrained', patience=20)
            print("trained")
            try:
                with session.as_default():
                    with session.graph.as_default():
                        score = model.evaluate()

                        model.save_model('trafficModels')
                        print('Test loss: ' + str(round(score[0], 3)))
                        print('Test accuracy ' + str(round(score[1], 3)) + " (+/-" + str(numpy.std(round(score[1], 3))) + ")")
                        plt.plot(stats['train_loss'])
                        plt.plot(stats['val_loss'])
                        plt.title('model loss')
                        plt.xlabel('epoch')
                        plt.ylabel('loss')
                        plt.legend(['train', 'test'], loc='upper left')
                        plt.show()
                        print(stats)
            except Exception as ex:
                logger.log('Error s ', ex, ex.__traceback__.tb_lineno)
        except Exception as e:
            logger.error("Exception occurred", exc_info=True)

'''
    name- name of the training data type (i.e packets or flows)
    Function lets you choose the data to be used for retraining
'''
def get_training_data(name):
    global ROOT_DIR
    name = name.replace('Models','Data')
    print(name)
    dataFiles = os.listdir(os.path.join(ROOT_DIR, name))
    chosenFile = None
    while chosenFile not in dataFiles:
        print("Choose a data file index to be used for training:\n")
        for i in range(len(dataFiles)):
            print(str(i)+". "+str(dataFiles[i]))
        chosenFile = input("\n Data:\n")
        if int(chosenFile) not in range(len(dataFiles)):
            print("Please choose an index")
        else:
            chosenFile = dataFiles[int(chosenFile)]
            print(chosenFile)
    if name == 'trafficData' and chosenFile != "final dataset.arff":
        data = pd.read_csv(name+"/"+chosenFile, delimiter=',')
        fieldNames = ['Source IP', 'Dest IP', 'Source Port', 'Dest Port',
        'Packet Length', 'Packets/Time', 'Highest Layer', 'Transport Layer', 'target']
        return data[fieldNames]
    elif name == 'trafficData' and chosenFile == "final dataset.arff":
        data = arff.loadarff('trafficData/final dataset.arff')
        df = pd.DataFrame(data[0])
        keep = ['SRC_ADD', 'DES_ADD', 'FROM_NODE', 'TO_NODE', 'NUMBER_OF_BYTE', 'PKT_SIZE', 'PKT_RESEVED_TIME',  'PKT_SEND_TIME', 'PKT_TYPE', 'PKT_CLASS']
        final = df[keep]
        final.columns = ['Source Port', 'Dest Port', 'Source IP', 'Dest IP', 'Byte Size', 'Packet Length', 'Received Time', 'Packets/Time', 'Packet Type', 'target']
        return final
    else:
        data = pd.read_csv(name+"/"+chosenFile, delimiter=',')
        return data


def choose_training_type(model, folder):
    global ROOT_DIR
    retraining = input("Would you like to retrain a new model or add onto the " +
        "old model?\n Choose n for new or o for old:\n")
    if retraining != 'n' and retraining != 'o':
        print("Choose one of the allowed answers")
        choose_training_type(model, folder)
    elif retraining == 'n':
        retrain_model(model, get_training_data(folder))
    elif retraining == 'o':
        models = os.listdir(os.path.join(ROOT_DIR, folder))
        model.model.load_weights(folder + "/" + choose_model(models , folder))
        retrain_model(model, get_training_data(folder))

'''
    Allows you to choose the type of model you want to retrain
'''
def train_model():
    modelToTrain = input("Which model would you like to train? The packets(p) or " +
        "the flow(f) one?\n Choose p or f:\n")
    if modelToTrain != 'p' and modelToTrain != 'f':
        print("Choose one of the allowed answers")
        train_model()
    elif modelToTrain == 'p':
        global modelPacket
        choose_training_type(modelPacket, 'trafficModels')
    elif modelToTrain == 'f':
        global modelFlow
        choose_training_type(modelFlow, 'flowModels')

'''
    Changes the currently used model for one particular
    detector to another existing model
'''
def change_model(type):
    types = ["traffic", "flow"]
    name = types[type]
    global ROOT_DIR
    models = os.listdir(os.path.join(ROOT_DIR, name +'Models'))
    if len(models) == 0:
        print("\nYou must first create a " + name +" model\n")
        start()
    else:
        src = os.path.join(ROOT_DIR, name + "Models/" + choose_model(models, name))
        dst = os.path.join(ROOT_DIR, name +"Models/currentModel.h5")
        if "currentModel.h5" in models:
            os.remove(dst)
        copyfile(src, dst)
        if name == 'traffic':
            global modelPacket
            modelPacket = modelPacket.model.load_weights('trafficModels/currentModel.h5')
        else:
            global modelFlow
            modelFlow = modelFlow.model.load_weights('flowModels/currentModel.h5')
        start()

def start():
    global logger, ROOT_DIR
    #choosing the version
    version = 'start'
    try:
        while version not in range(1,7):
            version = int(input("\nWhat do you want to do?\n " +
                "Run the detector? (1)\n " +
                "Train a model? (2)\n " +
                "Change the currently used model? (3)\n " +
                "List the blocked Ip addresses? (4)\n" +
                "Compute the PCA of a dataset? (5)\n" +
                "Initialize database? (6)" +
                "\n Run: "))
            if version not in range(1,7):
                print(version)
                print("Please choose between the values displayed!")
        if version == -1:
            run_CICFlowMeter()
        elif version == 1:
            global ROOT_DIR
            trafficModels = os.listdir(os.path.join(ROOT_DIR, 'trafficModels'))
            if len(trafficModels) == 0:
                print("\nYou must first create a packets model\n")
                #remove this
                start()
                print("You selected a packets model\n")
            elif "currentModel.h5" in trafficModels:
                global modelPacket
                try:
                    with session.as_default():
                        with session.graph.as_default():
                            modelPacket.load_model(ROOT_DIR +'/trafficModels/currentModel.h5')
                            modelPacket.model._make_predict_function()
                except Exception as e:
                    print(e)
            else:
                change_model(0)

            flowModels = os.listdir(os.path.join(ROOT_DIR, 'flowModels'))
            if len(flowModels) == 0:
                print("\nYou must first create a flow model\n")
                #remove this
                start()
                print("You selected a flow model\n")
            elif "currentModel.h5" in flowModels:
                global modelFlow
                try:
                    with session.as_default():
                        with session.graph.as_default():
                            print("Here")
                            modelFlow.load_model(ROOT_DIR +'/trafficModels/currentModel.h5')
                            modelFlow.model._make_predict_function()
                except Exception as e:
                    print(e)
            else:
                change_model(1)
            print(modelFlow)
            print(modelPacket)
            read_and_analize_traffic()
        elif version == 2:
            train_model()
        elif version == 3:
            type = 0
            while int(type) not in range(1,3):
                type = input('Change the \n ' +
                 '1. Traffic model\n ' +
                 '2. Flow model\n')
                if int(type) not in range(1,3):
                    print("Please choose one of the indexes")
            change_model(int(type)-1)
        elif version == 4:
            utils.listBlockedIps()
            type = 'c'
            while type != 'y' and type != 'n':
                type = input('Would you like to remove a block? (y/n)\n')
                if type != 'y' and type != 'n':
                    print("Please choose \'y\' or \'n\'\n")
            if type == 'n':
                start()
            else:
                names = input('Please write one or more of the above ip addresses' +
                ', separated by a comma followed by a space\n')
                name = names.split(', ')
                for i in name:
                    print(i)
                    utils.unblockIp(i)
                start()
        elif version == 5:
            c = rtm.chooseClass()
            c.train()
            start()
        elif version == 6:
            dtb.main()
            start()
        else:
            exit()

    except Exception as e :
        logger.error("Exception occurred", exc_info=True)
        print("Please choose between the values displayed!")
        start()

    #
    #live read
    #create a database called NEW_FLOW
    #in new flow keep the full dataset structure
    #read traffic
    #create flow-ID
start()
#watch_flow()
#run_CICFlowMeter()
