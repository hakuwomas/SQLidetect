from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix
from sklearn.metrics import mean_squared_error
import random
import numpy as np
import pandas as pd
from math import sqrt
import joblib
import time

class_names = ['legal', 'anomaly']
class_label = {
    'legal': 1,
    'anomaly': -1
}

legal_data = pd.read_csv(
    'l_data.csv'
)

legal_data = legal_data.sample(frac=1)


X = []
y = []

for i in range(0, len(legal_data)):
    y.append(1)

anomaly_data = pd.read_csv(
    'all_data.csv'
)



#anomaly_data.drop_duplicates(subset=['query_len'], keep=False)

for i in range(0, len(anomaly_data)):
    y.append(-1)

#data = legal_data.append(anomaly_data)
legal_data = legal_data.values.tolist()
anomaly_data = anomaly_data.values.tolist()
X = []

for vec in anomaly_data:
    legal_data.append(vec)
#data.drop(columns=['insert', 'update', 'outer', 'left', 'right', 'full'], inplace=True)
X = legal_data


def result():
    start = time.time()

    for epoch in range(0, 10):
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.4, random_state=epoch)
        
        clf.fit(X_train, y_train)
        print(clf.score(X_test, y_test))

    finish = time.time() - start

    y_pred = clf.predict(X)

    tn, fp, fn, tp = confusion_matrix(y, y_pred).ravel()

    print('\n')

    print("Time: " + str(finish))
    print("True Positive = " + str(tp))
    print("False Positive = " + str(fp))
    print("True Negative = " + str(tn))
    print("False Negative = " + str(fn))    


    try:
        mathews = (tp * tn - fp * fn) / \
                  sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))

        print('Mathews coef = ' + str(mathews))

        rmse = sqrt(mean_squared_error(y, y_pred))

        print('RMSE = ' + str(rmse))
    except:
        pass

    print('\n')
    print('################################################################################')
    print('\n')

##############################################################################################################



#hidden_layer_neuron_count = 6
#clf = MLPClassifier(solver='lbfgs', alpha=1e-5,
                    #hidden_layer_sizes=(17, hidden_layer_neuron_count, hidden_layer_neuron_count, hidden_layer_neuron_count, 2), random_state=1)
#print('MLP')
#result()

###############################################################################################################

#from sklearn import svm

#C = 1.0
#clf = svm.SVC(kernel='linear', C=C)

#print('SVM')
#result()

###############################################################################################################

from sklearn.ensemble import RandomForestClassifier

clf = RandomForestClassifier(n_estimators=100, 
                               bootstrap = True,                               
                               max_features = 'sqrt')

print('RANDOM FOREST')
result()

###############################################################################################################

#from sklearn.neighbors import KNeighborsClassifier

#clf = KNeighborsClassifier(n_neighbors=3)

#print('KNN')
#result()

###############################################################################################################

#from sklearn.naive_bayes import GaussianNB

#clf = GaussianNB()

#print('NB')
#result()

###############################################################################################################

#from sklearn.gaussian_process import GaussianProcessClassifier
#from sklearn.gaussian_process.kernels import RBF

#kernel = 1.0 * RBF(1.0)
#clf = GaussianProcessClassifier(kernel=kernel,
 #       random_state=0)

filename = 'random_forest_model.sav'
joblib.dump(clf, filename)




