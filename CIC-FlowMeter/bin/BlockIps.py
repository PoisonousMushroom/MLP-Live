import DbSetUp as db
from scipy.io import arff
import pandas as pd
import numpy as np
import DbSetUp as db

class BlockedIp():
    def __init__(self):
        unbanTime = 3 #days
        self.mydb, self.mycursor = db.getdb_cursor()
        #NOT IMPLEMENTED
