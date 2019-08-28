from keras.layers import Dense, Dropout
from keras.models import Sequential
from keras.optimizers import SGD, RMSprop
from keras import backend as K
import keras
import os
import time

'''
    record the time it takes to finalize the computation for an epoch
'''
class TimeHistory(keras.callbacks.Callback):
    def on_train_begin(self, logs={}):
        self.times = []

    def on_epoch_begin(self, batch, logs={}):
        self.epoch_time_start = time.time()

    def on_epoch_end(self, batch, logs={}):
        self.times.append(time.time() - self.epoch_time_start)


'''
    MLP class for the creation of a feedforward neural network
'''
class MLP:
    '''
        Builds a feedforward neural network.

        Parameters:
            layers      list, number of hidden units in each layer
        Optional:
            hid_act     hidden activation function
            out_act     output activation function
            dropout     dropout value
            loss        what loss function to use
            metrics     what metrics to use for evaluation
    '''
    def __init__(self, layers, input_dim, output_dim=2, optimizer='rms', hid_act='tanh',
                 out_act='softmax', dropout=None,
                 loss='categorical_crossentropy', metrics=['accuracy']):
        # check input
        assert len(layers) > 0

        # preprocess optimizer
        if isinstance(optimizer, str):
            if optimizer == 'sgd':
                optimizer = SGD(lr=0.01, decay=1e-6,
                                momentum=0.9, nesterov=True)
            elif optimizer == 'rms':
                optimizer = RMSprop()
            else:
                raise ValueError('Invalid optimizer')

        # save parameters
        self.hid_act = hid_act
        self.out_act = out_act
        self.loss = loss
        self._layers = layers.copy()

        # preprocess the layers
        if dropout:
            layers = [int(e / dropout) for e in layers]

        # create the model
        self.model = Sequential()

        # add first hidden layer
        layer = Dense(layers[0], activation=hid_act, input_dim=input_dim)
        self.model.add(layer)
        if dropout:
            dropout_layer = Dropout(dropout)
            self.model.add(dropout_layer)

        # add subsequent layers
        for i in range(1, len(layers)):
            layer = Dense(layers[i], activation=hid_act)
            self.model.add(layer)
            if dropout:
                dropout_layer = Dropout(dropout)
                self.model.add(dropout_layer)

        # add output layer
        output_layer = Dense(output_dim, activation=out_act)
        self.model.add(output_layer)

        # setup optimizer
        self.optimizer = optimizer

        # compile model
        self.model.compile(loss=loss,
                           optimizer=self.optimizer,
                           metrics=metrics)

    def load_data(self, data):
        # load the data
        self.x_train, self.x_test, self.y_train, self.y_test = data
        self.data = data

    '''
        Train the MLP.

        Parameters:
            epochs      how many epochs to train
            batch_size  size of batches

        Returns:
            hist        history object for training losses
    '''
    def train(self, epochs, batch_size, input_dim, trainingFile, patience=0):
        if not os.path.exists(trainingFile):
            os.makedirs(trainingFile)
        checkpoint_path=trainingFile + '/cp-{epoch:04d}.ckpt'

        model = None
        if trainingFile == 'filePacketTrained':
            model = MLP([10,10], input_dim, optimizer='rms')
        else:
            model = MLP([100, 100], input_dim, hid_act='relu')
        model.load_data(self.data)
        model.model.save_weights(checkpoint_path.format(epoch=0))
        # time callback
        callbacks = [
            TimeHistory(),
            keras.callbacks.ModelCheckpoint(checkpoint_path, monitor='val_acc', mode='max',
                                                 save_weights_only=True,
                                                 verbose=1)

        ]

        if patience > 0:
            epochs = 1000
            callbacks.append(
                keras.callbacks.EarlyStopping(monitor='val_loss',
                                              patience=patience,
                                              restore_best_weights=True)
            )
        try:
            # train the model
            hist = self.model.fit(self.x_train,
                                  self.y_train,
                                  epochs=epochs,
                                  batch_size=batch_size,
                                  validation_split=0.2,
                                  callbacks=callbacks)

            # extract times
            times = callbacks[0].times

            # extract history
            hist = hist.history

            # save all stats in one dictionary
            stats = {
                'epoch': [], 'time': [], 'val_loss': [],
                'val_acc': [], 'train_loss': [], 'train_acc': [],
                'comments': []
            }
            for i in range(len(times)):
                comments = '[{}]'.format(', '.join(map(str, self._layers)))
                comments += ', {}, {}, {}, {}, patience {}'.format(
                    self.hid_act, self.out_act, self.loss, str(self.optimizer),
                    patience
                )
                stats['epoch'] += [i + 1]
                stats['time'] += ['{:.3f}'.format(times[i])]
                stats['val_loss'] += ['{:.4f}'.format(hist['val_loss'][i])]
                stats['val_acc'] += ['{:.4f}'.format(hist['val_acc'][i])]
                stats['train_loss'] += ['{:.4f}'.format(hist['loss'][i])]
                stats['train_acc'] += ['{:.4f}'.format(hist['acc'][i])]
                stats['comments'] += [comments]

            K.clear_session()
            # return statistics dictionary
            return stats
        except Exception as e:
            print("DOn't know what happened")
            print(e)

    '''
        Save the finished model/ epoch in a file
    '''
    def save_model(self, path):
        if not os.path.exists(path):
            os.makedirs(path)
        filenums = len(os.listdir(path))
        i = filenums + 1 if filenums == 0 else filenums
        self.model.save_weights(path + '/model_{}.h5'.format(i))

    '''
        save new model to be used in analysis
    '''
    def save_current_model(self, path):
        os.remove(path + '/currentModel.h5')
        self.model.save_weights(path + '/currentModel.h5')

    def evaluate(self):
        return self.model.evaluate(self.x_test, self.y_test, verbose=100)

    '''
        Load a previously saved model
    '''
    def load_model(self, place):
        self.model.load_weights(place)
