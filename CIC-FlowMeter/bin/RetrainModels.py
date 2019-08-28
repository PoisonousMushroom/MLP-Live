import multiprocessing
import logging
import time
import DbSetUp as dtb
import Utils as utils
import MLP as mlp
import os
import pandas as pd
from shutil import copyfile
from keras import utils as U
from sklearn.model_selection import train_test_split
from scipy.io import arff
import socket, struct
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
from blaze import data, join, symbol, dshape
from odo import odo
import numpy as np
from sklearn.metrics import classification_report,confusion_matrix
from collections import Counter

#root directory
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

columnsPackets = ['id', 'Flow_ID', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port',
    'Protocol', 'Packet Length', 'Packets/Time', 'Highest Layer', 'Transport Layer',
    'Received_Time_Diff', 'Predicted_Time', 'Handled_Time', 'Predict', 'Hits/Time']
'''
Class used to retrain flom models
'''
class retrainFlowModel(multiprocessing.Process):
    def __init__(self, *args, **kwargs):
        super(retrainPacketModel, self).__init__(*args, **kwargs)
        print(args)
        print(kwargs)
        self.lock = kwargs['args'][1]
        self.db = kwargs['args'][0]
        self.mlp = mlp.MLP([100,100], 147)

    # function using _stop function
    def stop(self):
        print("terminated " + multiprocessing.current_process().name)
        self.terminate()
        self.join()


    def run(self):
        print("here")
        logger = logging.getLogger()
        logger.info("Waiting on "+ multiprocessing.current_process().name)
        self.lock.acquire()
        logger.info("Lock was aquired for training of the packet model on "+ multiprocessing.current_process().name)
        logger.info("Retraining packet")
        type = ''
        if self.db == 'finalFlow':
            print("full train")
            type = 'fully trained'
        else:
            type = 'refit'
            self.mlp.model.load_weights("flowModels/currentModel.h5")
            self.mlp.model._make_predict_function()
        global ROOT_DIR
        #save the current model state / uncomment after done  ## DEBUG:
        models = len(os.listdir(os.path.join(ROOT_DIR, 'flowModels')))-1
        src = os.path.join(ROOT_DIR, "flowModels/currentModel.h5")
        dst = os.path.join(ROOT_DIR, "flowModels/Model"+str(models)+".h5")
        copyfile(src, dst)

        #self.mlp.model.load_weights("trafficModels/currentModel.h5")
        data = pd.DataFrame(dtb.getFlows(self.db))
        data.columns = utils.getFlowCols()

        #get existent flows for the computation of targets
        packets = pd.DataFrame(dtb.getSomePacketsCols('finalPackets',['Flow_ID','Predict']), columns = ['Flow_ID', 'Predict'])

        cols = ['Flow_ID', 'Label']
        targets = utils.getTargetsF(data[cols], packets)
        targets = U.to_categorical(targets, num_classes=2)

        remove = ['id', 'Predicted_Time', "Handled_Time", "Label", 'Bwd Pkts/s', 'Pkt Len Mean']
        df = utils.to_one_hot_encoding(data).drop(remove, axis=1)
        df_num = df.apply(pd.to_numeric)
        df_num = df_num.select_dtypes(['number'])
        dataset = df_num.to_numpy()

        #split training dataset
        data = train_test_split(dataset, targets, test_size=0.2, random_state=53)
        if type == 'refit':
            start_time = timer()
            self.mlp.model.fit(data[0],data[2])
            end_time = timer()
            time_taken = end_time - start_time
            predictions = mlp.predict(data[1])
            print()
            hostile = 0
            safe = 0
            for check in predictions:
                if np.argmax(check) == 1:
                    hostile += 1
                else:
                    safe += 1
            print("Normal Flow: ", safe)
            print("Attack Flow: ", hostile)
            print("Time Taken:", time_taken)
            print("Confusion Matrix: ", "\n", confusion_matrix(data[3],predictions))
            print()
            print ("Classification Report: ", "\n",  classification_report(data[3],predictions))
            print()
            dtb.insertPTable(self.db)
        else:
            #load data
            self.mlp.load_data(data)

            #train
            #uncomment this when done # # DEBUG:

            stats = self.mlp.train(20, 128, 147, 'flowModels', patience = 50)

            logger.info(" New traffic model " + type + " with accuracy: " + str(stats['val_acc'][len(stats)-5]) + " and loss: " + str(stats['val_loss'][len(stats)-5]))
            logger.info("   The mean accuracy and deviations are: " + str(numpy.mean(stats['val_acc'])) + "\% (+/-" + str(numpy.std(stats['val_acc'])) + ")")

        self.mlp.save_current_model('flowModels')

        if type == 'refit':
            dtb.insertFTable(self.db)
        self.lock.release()
        print("There")
        logging.info("Lock was released for training of the flow model on "+ multiprocessing.current_process().name)


'''
THis represents the class used to retrain or refit the packet models
'''
class retrainPacketModel(multiprocessing.Process):
    def __init__(self, *args, **kwargs):
        super(retrainPacketModel, self).__init__(*args, **kwargs)
        print(args)
        print(kwargs)
        self.lock = kwargs['args'][1]
        self.db = kwargs['args'][0]
        self.mlp = mlp.MLP([100,100], 8, out_act='tanh')

    # function using _stop function
    def stop(self):
        print("terminated " + multiprocessing.current_process().name)
        self.terminate()
        self.join()


    def run(self):
        print("here")
        logger = logging.getLogger()
        logger.info("Waiting on "+ multiprocessing.current_process().name)
        self.lock.acquire()
        logger.info("Lock was aquired for training of the packet model on "+ multiprocessing.current_process().name)
        logger.info("Retraining packet")
        type = ''
        if self.db == 'finalPackets':
            print("full train")
            type = 'fully trained'
        else:
            type = 'refit'
            self.mlp.model.load_weights("trafficModels/currentModel.h5")
            self.mlp.model._make_predict_function()
        global ROOT_DIR
        #save the current model state / uncomment after done  ## DEBUG:
        models = len(os.listdir(os.path.join(ROOT_DIR, 'trafficModels')))-1
        src = os.path.join(ROOT_DIR, "trafficModels/currentModel.h5")
        dst = os.path.join(ROOT_DIR, "trafficModels/Model"+str(models)+".h5")
        copyfile(src, dst)

        #self.mlp.model.load_weights("trafficModels/currentModel.h5")
        data = pd.DataFrame(dtb.getPackets(self.db))
        global columnsPackets
        data.columns = columnsPackets

        #get existent flows for the computation of targets
        flows = pd.DataFrame(dtb.getSomeFlowCols('finalFlow',['Flow_ID','Label']), columns = ['Flow_ID', 'Label'])

        cols = ['Flow_ID', 'Predict']
        targets = utils.getTargets(data[cols], flows)
        targets = U.to_categorical(targets, num_classes=2)

        remove = ['id', 'Predicted_Time', "Handled_Time", "Predict"]
        encodedData = data.drop(remove, axis=1).apply(lambda x: utils.labelEncoder(x, 'Training')[0], axis=1)
        encodedData.columns = utils.getPacketNames()
        dataset = encodedData.select_dtypes(['number']).to_numpy()

        #split training dataset
        data = train_test_split(dataset, targets, test_size=0.2, random_state=53)

        #load data
        self.mlp.load_data(data)

        #train
        #uncomment this when done # # DEBUG:
        if type == 'refit':
            start_time = timer()
            self.mlp.model.fit(data[0],data[2])
            end_time = timer()
            time_taken = end_time - start_time
            predictions = mlp.predict(data[1])
            print()
            hostile = 0
            safe = 0
            for check in predictions:
                if np.argmax(check) == 1:
                    hostile += 1
                else:
                    safe += 1
            print("Normal Packets: ", safe)
            print("Attack Packets: ", hostile)
            print("Time Taken:", time_taken)

            print("Confusion Matrix: ", "\n", confusion_matrix(data[3],predictions))
            print()
            print ("Classification Report: ", "\n",  classification_report(data[3],predictions))
            print()
            dtb.insertPTable(self.db)
        else:
            stats = self.mlp.train(20, 128, 8, 'trafficModels', patience = 50)

            logger.info(" New traffic model " + type + " with accuracy: " + str(stats['val_acc'][len(stats)-5]) + " and loss: " + str(stats['val_loss'][len(stats)-5]))
            logger.info("   The mean accuracy and deviations are: " + str(numpy.mean(stats['val_acc'])) + "\% (+/-" + str(numpy.std(stats['val_acc'])) + ")")

        self.mlp.save_current_model('trafficModels')

        self.lock.release()
        print("There")
        logging.info("Lock was released for training of the packet model on "+ multiprocessing.current_process().name)

def to_encode(df):
    a = utils.time_to_nb(df['Timestamp'])
    return df.drop_field('Timestamp'), a

'''
     This code is created to compute the PCA of the packet and flow models.
'''
class chooseClass():
    # {Normal,UDP-Flood,Smurf,SIDDOS,HTTP-FLOOD}
    # pkt type {tcp,ack,cbr,ping}
    def __init__(self):
         self.type = input("Choose training (Packet or Flow)")

    def train(self):
         if self.type == 'p' or self.type == 'Packet' or self.type == 'P':
             #info = arff.loadarff('trafficData/final dataset.arff')
             #self.df = pd.DataFrame(info[0])

             info = pd.read_csv("trafficData/Combined (2).csv", delimiter=',')
             reorder = ['Source Port', 'Dest Port', 'Packet Length', 'Packets/Time', 'Source IP', 'Dest IP', 'Highest Layer', 'Transport Layer']
             self.x = info[reorder]
             self.y = pd.DataFrame(info['target'])
             self.x =  self.x.apply(lambda x: utils.labelEncoder(x, 'Training')[0], axis=1)
             self.y = U.to_categorical(self.y, num_classes=2)
             a = StandardScaler().fit_transform(self.x)
             pca = PCA(n_components=2)
             fit = pca.fit(a)
             print("Explained Variance: " + str(fit.explained_variance_ratio_))
             print("The components are")
             print(fit.components_)
             final = pd.DataFrame(pca.components_, columns=self.x.columns, index = ['PC-1','PC-2'])
             for i in final:
                 print(i)
                 print(final[i])
         else:
             dta = data('flowData/unbalaced_20_80_dataset.csv')
             self.df = dta.drop_field("Unnamed: 0")
             self.df = self.df.drop_field("Flow ID").drop_field("Label")
             self.x, time = to_encode(self.df)
             final = []
             ln = 0
             fields = []
             v = 0
             for i in self.x.fields:
                 b = self.x[i]
                 fields += i
                 a = utils.get(b)
                 if ln == 0:
                     ln = len(a)
                     ln2 = len(self.x.fields) + len(time.columns)
                     final = [[0 for x in range(ln2)] for y in range(ln)]
                 if i == "Src IP" or i == "Dst IP":
                     for j in range(ln):
                        final[j][v] = utils.ip2int(a[j][0])
                 else:
                     for j in range(ln):
                         final[j][v] = a[j][0]
                 v += 1
             for i in time:
                 fields +=  i
                 a = time[i]
                 for j in range(ln):
                     final[j][v] = int(a[j])
                 v += 1
             final = pd.DataFrame(final, columns=fields)
             final = final.to_numpy()
             #print(self.x.peek())
             #self.x = self.x.to_numpy()
             #print(self.x.peek())
             a = StandardScaler().fit_transform(final)
             pca = PCA(n_components=2)
             fit = pca.fit(a)
             print("Explained Variance: " + str(fit.explained_variance_ratio_))
             print("The components are")
             print(fit.components_)
             final = pd.DataFrame(pca.components_, columns=self.x.columns, index = ['PC-1','PC-2'])
             for i in final:
                 print(i)
                 print(final[i])

'''
The code under this area is used in order to compute the confusion and the classification_report
of the flow models. Due to the large size of the testing file, the flows had to be
read in batches
'''
lf = pd.read_csv('flowData/unbalaced_20_80_dataset.csv', nrows=0, delimiter=",")
lav = []
r = dict()
err = 1
stop = False

def val(x):
    if x != 'Infinity':
        return x
    else:
        return

def read_chunks(epoch_i, len_file, n_chunks):
    mlpt =  mlp.MLP([100,100], 147)
    print(epoch_i)
    a=[('Flow Byts/s', 'Flow Pkts/s')]
    for i in a:
        r[i] = np.array([[0,0],[0,0]])
    mlpt.model.load_weights(os.path.join('flowModels', epoch_i))
    global err, stop, lav
    chunk_i = 0
    while chunk_i < n_chunks:
      print(chunk_i)
      # compute offset and number of rows to read
      offset = chunk_i * int(len_file / n_chunks)
      n_rows = int(len_file / n_chunks)
'''
    This should only be uncomented if one wants to attempt to check the pca of a model
'''
#c = chooseClass()
#input = input("Retrain file run?")
#if input == "Yes" or input == "y" or input == "Y":
    #c.train()
      global lf
      if offset == 0:
        df = pd.read_csv('flowData/unbalaced_20_80_dataset.csv', skiprows=offset+1, nrows=n_rows,
                        names=lf.columns.values)
      else:
        df= pd.read_csv('flowData/unbalaced_20_80_dataset.csv', skiprows=offset, nrows=n_rows,
                        names=lf.columns.values)
      #df = df.append(pd.read_csv('final_dataset.csv',
       #                          skiprows=int(12794627/2)+offset,
        #                         names=lf.columns.values, nrows=n_rows)
         #              , ignore_index=True)
      df = df.drop("Unnamed: 0", axis=1)

      # get targets
      targets = np.array(df['Label'] == 'ddos')
      targets = U.to_categorical(targets, num_classes=2)

      #removes redundant data
      remove = ["Src IP", "Dst IP", "Timestamp",'Flow ID', 'Label']
      df = utils.to_one_hot_encoding(df).drop(remove, axis = 1)
      max = 0
      for i in a:
                  gt = df.drop([i[0],i[1]], axis= 1)
                  df_num = gt.apply(pd.to_numeric)
                  df_num = df_num.select_dtypes(['number'])
                  #print(df_num)
                  dataset = df_num.to_numpy()
                  data = train_test_split(dataset, targets, test_size=0.2, random_state=53)
                  predictions = mlpt.model.predict(dataset)
                  #print(predictions)
                  #print()
                  hostile = 0
                  safe = 0
                  for check in predictions:
                      if np.argmax(check) == 1:
                          hostile += 1
                      else:
                          safe += 1
                  #print("Normal Packets: ", safe)
                  #print("Attack Packets: ", hostile)
                  v = confusion_matrix(np.argmax(targets, axis=1),np.argmax(predictions, axis=1))
                  t = np.array([[0,0],[7616,0]])
                  if v[0][0] != t[0][0] or v[0][1] != t[0][1] or (v[1][0]!= t[1][0]  and v[1][1] != t[1][1] ) :
                      print(i)
                      print("Confusion Matrix: ", "\n", v)
                  r[i] = np.add(r[i], v)
                  print()
                  print ("Classification Report: ", "\n",  classification_report(np.argmax(targets, axis=1),np.argmax(predictions, axis=1)))
                  print()
      chunk_i += 1
    print(r)
# number of chunks for the reading of the file (issued due to incapacity to read in time)
#n_chunks = 100
#len_file = int(7616509) #984202 #int(7616509/10*4) #12794628 //only use the 20% ddos and 20% non ddos

# number of epochs to train the model for
#n_epochs = 1
#ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
#models = os.listdir(os.path.join(ROOT_DIR, 'flowModels'))
#for epoch_i in models:
  #read_chunks(epoch_i,len_file, n_chunks)
