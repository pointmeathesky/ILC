import numpy as np
import pandas as pd
from sklearn.utils import shuffle
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
import tensorflow as tf
from tensorflow.keras.layers import Input, Dense, LSTM
from tensorflow.keras.models import Model
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.layers import BatchNormalization, Bidirectional
import joblib

print("TensorFlow version:", tf.__version__)


def get_data():
    #get the data
    df1 = pd.read_csv("/home/rain/PycharmProjects/MachineLearning/sources.csv")
    df2 = pd.read_csv("/home/rain/PycharmProjects/MachineLearning/vuln.csv")
    #add labels to the not vulnerable data
    df1['Label'] = 0
    #combine the data
    comb = pd.concat([df1, df2], ignore_index=True)
    #shuffle the data
    shuf = shuffle(comb, random_state=42)
    return shuf


if __name__ == '__main__':
    dats = get_data()
    # split the data into training, validation, and test set
    train_data, test_data = train_test_split(dats, test_size=0.2, random_state=42)
    train_data, valid_data = train_test_split(train_data, test_size=0.125, random_state=42)

    # converting data into a format that's suitable for the model to process
    vectorizer = CountVectorizer(analyzer='char', max_features=10000)
    vectorizer.fit(train_data["Source"])

    # Convert the text data to character-level features
    X_train_vec = vectorizer.transform(train_data["Source"])
    X_valid_vec = vectorizer.transform(valid_data["Source"])
    X_test_vec = vectorizer.transform(test_data["Source"])

    # RNNs need to be 3d so data is changed from 2d arry to 3d array, the extra dimension represents the timestep for each sample
    # each charaacter is treated as a timestep
    X_train_vec = np.reshape(X_train_vec.toarray(), (X_train_vec.shape[0], 1, X_train_vec.shape[1]))
    X_valid_vec = np.reshape(X_valid_vec.toarray(), (X_valid_vec.shape[0], 1, X_valid_vec.shape[1]))
    X_test_vec = np.reshape(X_test_vec.toarray(), (X_test_vec.shape[0], 1, X_test_vec.shape[1]))

    # neural net architecture
    # input layer
    text_input = Input(shape=(1, X_train_vec.shape[2]), name='text')
    # LSTM layer
    lstm_layer = LSTM(100, return_sequences=True)(text_input)
    # batch normalization
    normalized_lstm = BatchNormalization()(lstm_layer)
    # dense layer (every node in the layer is connected to every node in the last layer) relu activation introduces nonlinearity
    dense_layer = Dense(128, activation='relu')(normalized_lstm)
    # output layer, sigmoid activation makes output be betwenn 0-1
    output_layer = Dense(1, activation='sigmoid', name="output")(dense_layer)

    # use inputs and outputs to construct a final model
    model = Model(inputs=[text_input], outputs=[output_layer])
    model.summary()

    METRICS = [
        tf.keras.metrics.BinaryAccuracy(name='accuracy'),
        tf.keras.metrics.Precision(name='precision'),
        tf.keras.metrics.Recall(name='recall')
    ]

    custom_learning_rate = 0.01
    optimizer = Adam(learning_rate=custom_learning_rate)
    model.compile(optimizer=optimizer, loss='binary_crossentropy', metrics=METRICS)

    y_train = train_data["Label"]
    y_valid = valid_data["Label"]
    y_test = test_data["Label"]

    # there is a data imbalance so adding weight to try to make up for it. when weights are the same the model will sometimes have a recall of 0
    weight_for_0 = 1.0
    weight_for_1 = 1.7
    weights = {0: weight_for_0, 1: weight_for_1}

    # train the model
    model.fit(X_train_vec, y_train, epochs=15, validation_data=(X_valid_vec, y_valid), class_weight=weights)

    # Evaluate the model
    model.evaluate(X_test_vec, y_test)

    # Saving the model
    model.save("trainedModel")
    # save the vectorizer to use when processing new data
    joblib.dump(vectorizer, "vectorizer.pkl")
