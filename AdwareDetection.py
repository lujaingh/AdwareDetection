#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import pandas as pd 
import numpy as np
import heapq
import io
import matplotlib.pyplot as plt 
import seaborn as sns 
import sklearn 
import re
import os, sys
from smalisca.core.smalisca_main import SmaliscaApp
from smalisca.modules.module_smali_parser import SmaliParser
import re
import os, sys
import subprocess
from os import listdir
from os.path import isfile, join
import subprocess
from pandas import read_csv
from sklearn.feature_selection import RFE
from sklearn.datasets import make_classification
from sklearn.feature_selection import SelectKBest
from sklearn.feature_selection import f_classif
import sklearn.model_selection as model_selection
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.decomposition import PCA
from numpy import set_printoptions
from sklearn.ensemble import VotingClassifier
from sklearn.utils import resample
from sklearn.feature_selection import SelectKBest
from sklearn.feature_selection import f_classif
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import AdaBoostClassifier
from sklearn.ensemble import BaggingClassifier
from sklearn.datasets import make_classification
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.model_selection import RepeatedStratifiedKFold
from sklearn.neighbors import NearestNeighbors
from sklearn.svm import LinearSVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import precision_recall_curve
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import roc_curve


# # api calls extraction

# In[3]:


from os import walk

_, _, filenames = next(walk(r'D:\Ms\SecSem\Security\paper\allapks\adware'))
filenames


# In[4]:


_, _, filenamesben = next(walk(r'D:\Ms\SecSem\Security\paper\allapks\benign'))
filenamesben


# In[5]:


##remove .apk from the path
for i in filenamesben:
    filenamesben[filenamesben.index(i)]=i[:-4]

    
for i in filenames:
    filenames[filenames.index(i)]=i[:-4]


# In[13]:


ismalware1=[]
c=['startService','getDeviceId','createFromPdu','getClassLoader',
'getClass','getMethod','getDisplayOriginatingAddress',
'getInputStream','getOutputStream','killProcess',
'getLine1Number','getSimSerialNumber','getSubscriberId',
'getLastKnownLocation','isProviderEnabled']

listbs=[]
listpkgs=[]
listres=[]


# In[14]:


counter=0
while counter<275:
    for bi in filenamesben:
        try:
            listpkgs.append(bi)
            usethispath= r"D:\Ms\SecSem\Security\paper\allapks\benign"+'\\'+bi
            app = SmaliscaApp()
            app.setup() 
            app.log.set_level('info')
            path=usethispath
            dirs = os.listdir(path)
            path =usethispath
            root=usethispath
            # This would print all the files and directories
            p = os.system("")
            for file in dirs:
                print(file)
                os.chdir(usethispath)
                os.system("java -jar " + "D:\\apktool.jar" + " d " + root + "/" + file)
            i=0
            location = usethispath
            #Specify file name suffix
            suffix = 'smali'
            #Create a new parser

            parser = SmaliParser(location, suffix)
            parser.run()
            results = parser.get_results()
            results1=re.findall(r'\'to_method\': \'(.*)\'\}',str(results))
            results2=re.sub('\'',"",str(results1))
            c=['startService','getDeviceId','createFromPdu','getClassLoader',
            'getClass','getMethod','getDisplayOriginatingAddress',
            'getInputStream','getOutputStream','killProcess',
            'getLine1Number','getSimSerialNumber','getSubscriberId',
            'getLastKnownLocation','isProviderEnabled']
            b=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
            print(results1)
            for C in c:
                if re.search(r''+C, str(results1)):
                    b[i]=1
                    print("Found")
                i=i+1
            print(b)
            ismalware1.append(0)
            listbs.append(b)
            
        except:
            b=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
            ismalware1.append(0)
            listbs.append(b)
   
            continue
        counter+=1
    
else:
        for bi in filenames:
            try:
                listpkgs.append(bi)
                usethispath= r"D:\Ms\SecSem\Security\paper\allapks\adware"+'\\'+bi
                app = SmaliscaApp()
                app.setup() #Set log level
                app.log.set_level('info')
                path=usethispath
                dirs = os.listdir(path)
                path =usethispath
                root=usethispath
                # This would print all the files and directories
                p = os.system("")
                for file in dirs:
                    print(file)
                    os.chdir(usethispath)
                    os.system("java -jar " + "D:\\apktool.jar" + " d " + root + "/" + file)
                i=0
                location = usethispath
                #Specify file name suffix
                suffix = 'smali'
                #Create a new parser

                parser = SmaliParser(location, suffix)
                parser.run()
                results = parser.get_results()
                results1=re.findall(r'\'to_method\': \'(.*)\'\}',str(results))
                results2=re.sub('\'',"",str(results1))
                c=['startService','getDeviceId','createFromPdu','getClassLoader',
                'getClass','getMethod','getDisplayOriginatingAddress',
                'getInputStream','getOutputStream','killProcess',
                'getLine1Number','getSimSerialNumber','getSubscriberId',
                'getLastKnownLocation','isProviderEnabled']
                b=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
                print(results1)
                for C in c:
                    if re.search(r''+C, str(results1)):
                        b[i]=1
                        print("Found")
                    i=i+1
                print(b)
                ismalware1.append(1)
                listbs.append(b)
                
            
            
            except:
                b=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
                ismalware1.append(1)
                listbs.append(b)

                continue
            counter+=1


# In[22]:


for i in listbs:
     del i[-1]
listbs


# In[23]:


da = pd.DataFrame(listbs,columns=c)
da


# In[24]:


da['apk']=listpkgs


# In[25]:


cols = list(da)#swipe columns,reorder

cols[15], cols[0] = cols[0], cols[15]
cols[16], cols[1] = cols[1], cols[16]
da=da.loc[:,cols]


# In[28]:


da.drop_duplicates(inplace=True)


# In[29]:


da.to_csv(r'D:\Ms\SecSem\Security\paper\apiall.csv')


# # permissions extraction

# In[198]:


data=pd.read_csv(r'D:\Ms\SecSem\Security\paper\New Microsoft Excel Worksheet.csv')
data.drop(columns=['test_permission'],inplace=True)
data.head()


# In[244]:


listOfListsapk=[]
listOfListsper=[]

listofapksM=[]
listofPermissionsM=[]
listofapksB=[]
listofPermissionsB=[]

ismalware=[]
c=0
files=['\Benign_2015','\dowgin','\ewind','\gooligan', '\kemoge','\koodous','\mobidash','\selfmite','\shuanet','\youmi']
for i in files: 
    c=0
    
    if i == '\Benign_2015':
        path = r"D:\Ms\SecSem\Security\paper\Benign_2015"
        dirs = os.listdir(path)
        root = path
        #This would print all the files and directories
        for file in dirs:

            print (file)
            listofapksB.append(file)
            os.chdir(path)
            os.system("java -jar " + "D:\\apktool.jar" + " d " + root+"/"+file)
            #This would copy all the permissions of files (both benign and malicious) in the directory
            #into a text file

            p = os.system("D:\\aapt.exe d permissions "+path+"/"+file+">> permissions{0}.txt".format(c))

            f = open(path+"\permissions{0}.txt".format(c), "r")
            l = f.readlines()
            listofPermissionsB.append(l)
            ismalware.append(0)
            c+=1
            f.close()
        listOfListsapk.append(listofapksB)
        listOfListsper.append(listofPermissionsB)
        print(p)
        listofapksB=[]
        listofPermissionsB=[]

    else:
        
   

        path =  r"D:\Ms\SecSem\Security\paper\Adware"+i

        dirs = os.listdir(path)
        root = path
        #This would print all the files and directories
        for file in dirs:
            print (file)
            listofapksM.append(file)
            os.chdir(path)
            os.system("java -jar " + "D:\\apktool.jar" + " d " + root+"/"+file)
            #This would copy all the permissions of files (both benign and malicious) in the directory
            #into a text file

            p = os.system("D:\\aapt.exe d permissions "+path+"/"+file+">> permissions{0}.txt".format(c))

            f = open(path+"\permissions{0}.txt".format(c), "r")
            l = f.readlines()
            listofPermissionsM.append(l)
            ismalware.append(1)
            c+=1
            f.close()
        listOfListsapk.append(listofapksM)
        listOfListsper.append(listofPermissionsM)
        listofapksM=[]
        listofPermissionsM=[]
        print(p)


# In[245]:


# remove index 0 from inner arrays"name of pkg"
l = listOfListsper
for i in l:
    for j in i:
        #print(j[0])
        try:
            if j[0].startswith('package:'):
                print(j[0])
                j.remove(j[0])
        except:
            continue
        #print(type(j))
        #del j[0]
        


# In[246]:


from itertools import chain

newlistapks=list(chain.from_iterable(listOfListsapk))
newlistapks


# In[247]:


listspernew=[e for sl in listOfListsper for e in sl]
listspernew


# In[248]:


for i in listspernew:
    for j in i:
        if(j.startswith('uses-permission')):
            
            i[i.index(j)]=j[23:-2]
            j=j[23:-2]
            print(j)
        else:
            i[i.index(j)]=j[12:-2]#starts with permission
            j=j[12:-2]
            print(j)
                
        


# In[249]:


listspernew


# In[250]:


len(newlistapks)


# In[251]:


len(ismalware)


# In[252]:


len(listspernew)


# In[253]:


df=data
is_apk = df['apk'] == 0
df_try = df[is_apk]
df=df.append([df_try]*2,ignore_index=True)#duplicate size of df
s=(df.sample(364))
s['apk']=newlistapks
s['type']=ismalware


# In[254]:


df=s
df.reset_index(drop=True, inplace=True)
df


# In[256]:


o=df
col = o.head(364 )#df
# creating a list of dataframe columns
clmn = list(col)
clmn.remove('apk')   
clmn.remove('type')  
c=0
for y in range(0,364):#each instance
    
    for i in clmn:#each column
        for g in listspernew[y]:#each item in each list in permission lists to each apk
            if i==g:
                col[i][y]=1#if permission is found
                print(col[i][y])


# In[257]:


cs=col.to_csv(r'D:\Ms\SecSem\Security\paper\csvs\perm.csv')
col


# In[4]:


df1=pd.read_csv(r'D:\Ms\SecSem\Security\paper\csvs\perm.csv')
da=pd.read_csv(r'D:\Ms\SecSem\Security\paper\apiall.csv')
df1.drop(columns='Unnamed: 0',inplace=True)
da['apk']=df1['apk']
df_keys = pd.merge(df1, da, left_on='apk', right_on='apk')
df_keys


# In[5]:


col=df_keys


# # Up sampling to handle imbalanced data

# In[6]:


sns.countplot(x = col['type'])


# In[7]:


print(col["type"].value_counts())
print('data is imbalanced')


# In[8]:


#    up sample
df_majority_train = col[col.type==0]
df_minority_train = col[col.type==1]
 
# upsample minority class
df_majority_downsampled = resample(df_minority_train , 
                                 replace=True,    # sample without replacement
                                 n_samples=275,     # to match minority class
                                 random_state=123) # reproducible results
 
# Combine minority class with downsampled majority class
df_downsampled_train = pd.concat([df_majority_downsampled, df_majority_train])
 
# Display new class counts
df_downsampled_train.type.value_counts()


# In[9]:


df_up_train=pd.DataFrame(df_downsampled_train)
df_up_train.reset_index(drop=True, inplace=True)
df_up_train


# # Methods
# ## Bagging and AdaBoosting
# ## two approaches for feature selection used:
# ## PCA,RFE

# ## 1.bagging 

# ##### rfe method for feature selection

# In[10]:


from sklearn.model_selection import learning_curve, GridSearchCV

def rfe(components):
    X=df_up_train.drop(columns=['apk','type'])#traindata
    y=df_up_train.type
    model = LogisticRegression(solver='lbfgs')#classifier expose "coef_" or "feature_importances_" attributes

    rfe = RFE(model, components)
    fit = rfe.fit(X, y)
    #print("Num Features: %d" % fit.n_features_)
    #print("Selected Features: %s" % fit.support_)
    #print("Feature Ranking: %s" % fit.ranking_)
 

    dfrfe=pd.DataFrame(df_up_train)
    c=0
    for i in fit.support_: 
        try:
            if(i==False):
                dfrfe.drop(dfrfe.columns[c], axis=1,inplace=True)
                c+=1
        except:
            pass

    return dfrfe     


# ### 1.a bagging(naive as base) with pca 20 components

# ##### grid search for base

# In[11]:


from sklearn.model_selection  import train_test_split
#X=rfe(150)#traindata
#Y=df_up_train.type
X=df_up_train.drop(columns=['apk','type'])#traindata
Y=df_up_train.type
pca = PCA( 10)
X =  pca.fit_transform(X)  


X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.4, random_state=4)


nb_classifier = GaussianNB()

params_NB = {'var_smoothing': np.logspace(0,-9, num=100)}#it has only 2 params
gs_NB = GridSearchCV(estimator=nb_classifier, 
                 param_grid=params_NB, 
                  # use any cross validation technique 
                 verbose=1, 
                 scoring='accuracy') 
gs_NB.fit(X_train, y_train)

gs_NB.best_params_


# In[12]:


from sklearn.metrics import roc_auc_score
seed = 8
kfold=RepeatedKFold(n_splits=3, n_repeats=2, random_state=1)  
acc,tpr,fpr,aucns,auclr =0,0,0,0,0
model=0

# initialize the base classifier 
base_cls =KNeighborsClassifier(n_neighbors=3)
#base is used with bagging
for train_index, test_index in kfold.split(X, Y):
    
    X_train, X_test = X[train_index], X[test_index]
    y_train, y_test = Y[train_index], Y[test_index] 
    # bagging classifier 

    model = BaggingClassifier(base_estimator = base_cls,
                             n_estimators=15, 
                             random_state = seed )
    model.fit(X_train, y_train)
    yhat = model.predict(X_test)
        
    probs = model.predict_proba(X_test)
    probs = probs[:,1]#take the first column for probs
     
    #find acc of model
    results = model_selection.cross_val_score(model, X_test, y_test, cv = kfold)
    
    
    auc = roc_auc_score(y_test, probs)
        
    ns_probs = [0 for _ in range(len(y_test))]#to find no skill probs
    lr_probs = model.predict_proba(X_test)
    # keep probabilities for the positive outcome only,coz that draws the curve below noskill line
    lr_probs = lr_probs[:, 1]
    # calculate scores
    ns_auc = roc_auc_score(y_test, ns_probs)
    lr_auc = roc_auc_score(y_test, lr_probs)
    # summarize scores
    aucns=ns_auc
    auclr=lr_auc
    # TPR FPR
    ns_fpr, ns_tpr, _ = roc_curve(y_test, ns_probs)
    lr_fpr, lr_tpr, _ = roc_curve(y_test, lr_probs)
    tpr=lr_tpr
    fpr=lr_fpr
        
    no_skill = len(y_test[y_test==1]) / len(y_test)#to draw prec recall curve(noskill line)




                
print('No Skill: ROC AUC=%.3f' % (aucns))
print('Bagging: ROC AUC=%.3f' % (auclr))        
# plot the roc curve for the model
plt.plot(ns_fpr, ns_tpr, linestyle='--', label='No Skill')
plt.plot(lr_fpr, lr_tpr, marker='.', label='ada')
# axis labels
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
# show the legend
plt.legend()
# show the plot
plt.show()        

column_names2 = ["TPR","FPR"]
dfres2 = pd.DataFrame(columns = column_names2)
dfres2["TPR"]=tpr
dfres2["FPR"]=fpr

column_names3 = [ "Acc"]
dfres3 = pd.DataFrame([   results.mean()],columns = column_names3)


# In[88]:


dfres2.loc[34]


# In[87]:


##find the biggest dif,,we want big diff btw fpr and tpr, not want only to have low fp or tp
##If there is no external concern about low TPR or high FPR, one option is to weight them equally
arr=tpr-fpr
maxElement = np.amax(arr)
result = np.where(arr == maxElement)#index of max diff
print(arr)
print(result)
maxElement


# In[177]:


dfres3


# ### 1.b bagging(naive as base) with pca 150 components

# ##### grid search for base

# In[162]:


from sklearn.model_selection  import train_test_split
#X=rfe(150)#traindata
#Y=df_up_train.type
X=df_up_train.drop(columns=['apk','type'])#traindata
y=df_up_train.type
pca = PCA( 10)
X =  pca.fit_transform(X)  
Y=df_up_train.type

X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.4, random_state=4)


nb_classifier = GaussianNB()

params_NB = {'var_smoothing': np.logspace(0,-9, num=100)}
gs_NB = GridSearchCV(estimator=nb_classifier, 
                 param_grid=params_NB, 
                  # use any cross validation technique 
                 verbose=1, 
                 scoring='accuracy') 
gs_NB.fit(X_train, y_train)

gs_NB.best_params_


# In[163]:


seed = 8
kfold=RepeatedKFold(n_splits=3, n_repeats=2, random_state=1)  
acc,tpr,fpr,aucns,auclr =0,0,0,0,0
model=0
# initialize the base classifier 
base_cls =GaussianNB(var_smoothing= 0.02310129700083159)
#base is used with bagging

for train_index, test_index in kfold.split(X, Y):
    
    X_train, X_test = X[train_index], X[test_index]
    y_train, y_test = Y[train_index], Y[test_index] 

    # bagging classifier 
    model = BaggingClassifier(base_estimator = base_cls,
                             n_estimators=15, 
                              random_state = seed )
    model.fit(X_train, y_train)
    yhat = model.predict(X_test)
        
    probs = model.predict_proba(X_test)
    probs = probs[:,1]#take the first column for probs
     

    #find acc of model
    results = model_selection.cross_val_score(model, X_test, y_test, cv = kfold)
    
    
    auc = roc_auc_score(y_test, probs)
        
    ns_probs = [0 for _ in range(len(y_test))]#to find no skill probs
    lr_probs = model.predict_proba(X_test)
    # keep probabilities for the positive outcome only,coz that draws the curve below noskill line
    lr_probs = lr_probs[:, 1]
    # calculate scores
    ns_auc = roc_auc_score(y_test, ns_probs)
    lr_auc = roc_auc_score(y_test, lr_probs)
    # summarize scores
    aucns=ns_auc
    auclr=lr_auc
    # TPR FPR
    ns_fpr, ns_tpr, _ = roc_curve(y_test, ns_probs)
    lr_fpr, lr_tpr, _ = roc_curve(y_test, lr_probs)
    tpr=lr_tpr
    fpr=lr_fpr
        
    no_skill = len(y_test[y_test==1]) / len(y_test)#to draw prec recall curve(noskill line)




        
        
print('No Skill: ROC AUC=%.3f' % (aucns))
print('Bagging: ROC AUC=%.3f' % (auclr))        
# plot the roc curve for the model
plt.plot(ns_fpr, ns_tpr, linestyle='--', label='No Skill')
plt.plot(lr_fpr, lr_tpr, marker='.', label='ada')
# axis labels
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
# show the legend
plt.legend()
# show the plot
plt.show()        



column_names2 = ["TPR","FPR"]
dfres2 = pd.DataFrame(columns = column_names2)
dfres2["TPR"]=tpr
dfres2["FPR"]=fpr

column_names3 = [ "Acc"]
dfres3 = pd.DataFrame([   results.mean()],columns = column_names3)


# In[164]:


dfres3


# In[666]:


dfres2.loc[39]


# In[664]:


##find the biggest dif,,we want big diff btw fpr and tpr, not want only to have low fp or tp
##If there is no external concern about low TPR or high FPR, one option is to weight them equally
arr=tpr-fpr
maxElement = np.amax(arr)
result = np.where(arr == maxElement)#index of max diff
print(arr)
print(result)
maxElement


# ### 1.c bagging(naive as base) with rfe 150 components

# ##### grid search for base

# In[13]:


from sklearn.model_selection  import train_test_split
X=rfe(150)#traindata
Y=df_up_train.type
#X=df_up_train.drop(columns=['apk','type'])#traindata
#y=df_up_train.type
#pca = PCA( 150)
#X =  pca.fit_transform(X)  
#Y=df_up_train.type

X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.4, random_state=4)


nb_classifier = GaussianNB()

params_NB = {'var_smoothing': np.logspace(0,-9, num=100)}
gs_NB = GridSearchCV(estimator=nb_classifier, 
                 param_grid=params_NB, 
                  # use any cross validation technique 
                 verbose=1, 
                 scoring='accuracy') 
gs_NB.fit(X_train, y_train)

gs_NB.best_params_


# In[14]:



seed = 8

kfold=RepeatedStratifiedKFold(n_splits=3, n_repeats=2, random_state=1)  
acc,tpr,fpr,aucns,auclr =0,0,0,0,0
model=0
# initialize the base classifier 
base_cls =GaussianNB(var_smoothing=.0008111308307896872)
#base is used with bagging


for train_index, test_index in kfold.split(X, Y):
    
    X_train, X_test = X.loc[train_index], X.loc[test_index]
    y_train, y_test = Y[train_index], Y[test_index] 

    

    # bagging classifier 
    model = BaggingClassifier(base_estimator = base_cls,
                             n_estimators=15, 
                              random_state = seed )
    model.fit(X_train, y_train)
    yhat = model.predict(X_test)
     

 
    
    probs = model.predict_proba(X_test)
    probs = probs[:,1]#take the first column for probs
     


    #find acc of model
    results = model_selection.cross_val_score(model, X_test, y_test, cv = kfold)
    

    
    auc = roc_auc_score(y_test, probs)
        
    ns_probs = [0 for _ in range(len(y_test))]#to find no skill probs
    lr_probs = model.predict_proba(X_test)
    # keep probabilities for the positive outcome only,coz that draws the curve below noskill line
    lr_probs = lr_probs[:, 1]
    # calculate scores
    ns_auc = roc_auc_score(y_test, ns_probs)
    lr_auc = roc_auc_score(y_test, lr_probs)
    # summarize scores
    aucns=ns_auc
    auclr=lr_auc
    # TPR FPR
    ns_fpr, ns_tpr, _ = roc_curve(y_test, ns_probs)
    lr_fpr, lr_tpr, _ = roc_curve(y_test, lr_probs)
    tpr=lr_tpr
    fpr=lr_fpr
        
    no_skill = len(y_test[y_test==1]) / len(y_test)#to draw prec recall curve(noskill line)




        
        
print('No Skill: ROC AUC=%.3f' % (aucns))
print('Bagging: ROC AUC=%.3f' % (auclr))        
# plot the roc curve for the model
plt.plot(ns_fpr, ns_tpr, linestyle='--', label='No Skill')
plt.plot(lr_fpr, lr_tpr, marker='.', label='ada')
# axis labels
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
# show the legend
plt.legend()
# show the plot
plt.show()        



column_names2 = ["TPR","FPR"]
dfres2 = pd.DataFrame(columns = column_names2)
dfres2["TPR"]=tpr
dfres2["FPR"]=fpr

column_names3 = [ "Acc"]
dfres3 = pd.DataFrame([   results.mean()],columns = column_names3)


# In[111]:


dfres2


# In[112]:


##find the biggest dif,,we want big diff btw fpr and tpr, not want only to have low fp or tp
##If there is no external concern about low TPR or high FPR, one option is to weight them equally
arr=tpr-fpr
maxElement = np.amax(arr)
result = np.where(arr == maxElement)#index of max diff
print(arr)
print(result)
maxElement


# In[15]:


dfres3


# ### 1.d bagging(naive as base) with rfe 170 components

# ##### grid search for base

# In[687]:


from sklearn.model_selection  import train_test_split
X=rfe(170)#traindata
Y=df_up_train.type
#X=df_up_train.drop(columns=['apk','type'])#traindata
#y=df_up_train.type
#pca = PCA( 150)
#X =  pca.fit_transform(X)  
#Y=df_up_train.type

X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.4, random_state=4)


nb_classifier = GaussianNB()

params_NB = {'var_smoothing': np.logspace(0,-9, num=100)}
gs_NB = GridSearchCV(estimator=nb_classifier, 
                 param_grid=params_NB, 
                  # use any cross validation technique 
                 verbose=1, 
                 scoring='accuracy') 
gs_NB.fit(X_train, y_train)

gs_NB.best_params_


# In[688]:



seed = 8
kfold=RepeatedStratifiedKFold(n_splits=3, n_repeats=2, random_state=1)  
acc,tpr,fpr,aucns,auclr =0,0,0,0,0
model=0
# initialize the base classifier 
base_cls =GaussianNB(var_smoothing=.00006579332246575683)
#base is used with bagging
for train_index, test_index in kfold.split(X, Y):
    
    X_train, X_test = X.loc[train_index], X.loc[test_index]
    y_train, y_test = Y[train_index], Y[test_index] 
    # bagging classifier 
    model = BaggingClassifier(base_estimator = base_cls,
                             n_estimators=15, 
                              random_state = seed )
    model.fit(X_train, y_train)
    yhat = model.predict(X_test)
    probs = model.predict_proba(X_test)
    probs = probs[:,1]#take the first column for probs
     


    #find acc of model
    results = model_selection.cross_val_score(model, X_test, y_test, cv = kfold)
    

    
    auc = roc_auc_score(y_test, probs)
        
    ns_probs = [0 for _ in range(len(y_test))]#to find no skill probs
    lr_probs = model.predict_proba(X_test)
    # keep probabilities for the positive outcome only,coz that draws the curve below noskill line
    lr_probs = lr_probs[:, 1]
    # calculate scores
    ns_auc = roc_auc_score(y_test, ns_probs)
    lr_auc = roc_auc_score(y_test, lr_probs)
    # summarize scores
    aucns=ns_auc
    auclr=lr_auc
    # TPR FPR
    ns_fpr, ns_tpr, _ = roc_curve(y_test, ns_probs)
    lr_fpr, lr_tpr, _ = roc_curve(y_test, lr_probs)
    tpr=lr_tpr
    fpr=lr_fpr
        
    no_skill = len(y_test[y_test==1]) / len(y_test)#to draw prec recall curve(noskill line)




        
        
print('No Skill: ROC AUC=%.3f' % (aucns))
print('Bagging: ROC AUC=%.3f' % (auclr))        
# plot the roc curve for the model
plt.plot(ns_fpr, ns_tpr, linestyle='--', label='No Skill')
plt.plot(lr_fpr, lr_tpr, marker='.', label='ada')
# axis labels
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
# show the legend
plt.legend()
# show the plot
plt.show()        



column_names2 = ["TPR","FPR"]
dfres2 = pd.DataFrame(columns = column_names2)
dfres2["TPR"]=tpr
dfres2["FPR"]=fpr

column_names3 = [ "Acc"]
dfres3 = pd.DataFrame([   results.mean()],columns = column_names3)


# In[689]:


dfres3


# In[690]:


dfres2


# In[691]:


##find the biggest dif,,we want big diff btw fpr and tpr, not want only to have low fp or tp
##If there is no external concern about low TPR or high FPR, one option is to weight them equally
arr=tpr-fpr
maxElement = np.amax(arr)
result = np.where(arr == maxElement)#index of max diff
print(arr)
print(result)
maxElement


# ### 1.e bagging(DT as base) with rfe 170 components

# ##### grid search for base

# In[154]:


from sklearn.model_selection  import train_test_split
X=rfe(170)#traindata
Y=df_up_train.type
#X=df_up_train.drop(columns=['apk','type'])#traindata
#y=df_up_train.type
#pca = PCA( 150)
#X =  pca.fit_transform(X)  
#Y=df_up_train.type

X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.4, random_state=4)


nb_classifier = DecisionTreeClassifier()

params_NB = {'criterion' : ['gini', 'entropy'],
            'max_depth' : [2,4,6,8,10,12,20,25,18]
             ,'max_features':[2,4,6,8,10,12,20,25,18]
            }
gs_NB = GridSearchCV(estimator=nb_classifier, 
                 param_grid=params_NB, 
                  # use any cross validation technique 
                 verbose=1, 
                 scoring='accuracy') 
gs_NB.fit(X_train, y_train)

gs_NB.best_params_


# In[155]:



seed = 8
kfold=RepeatedKFold(n_splits=3, n_repeats=2, random_state=1)  
acc,tpr,fpr,aucns,auclr =0,0,0,0,0
model=0
results=0
# initialize the base classifier 
base_cls =DecisionTreeClassifier(criterion='entropy',max_depth=25,max_features=18)
#base is used with bagging
for train_index, test_index in kfold.split(X, Y):
    
    X_train, X_test = X.loc[train_index], X.loc[test_index]
    y_train, y_test = Y[train_index], Y[test_index] 
    # bagging classifier 
    model = BaggingClassifier(base_estimator = base_cls,
                             n_estimators=15, 
                              random_state = seed )
    model.fit(X_train, y_train)
    yhat = model.predict(X_test)
    probs = model.predict_proba(X_test)
    probs = probs[:,1]#take the first column for probs
     


    #find acc of model
    results = model_selection.cross_val_score(model, X_test, y_test, cv = kfold)
    
        

    auc = roc_auc_score(y_test, probs)
        
    ns_probs = [0 for _ in range(len(y_test))]#to find no skill probs
    lr_probs = model.predict_proba(X_test)
    # keep probabilities for the positive outcome only,coz that draws the curve below noskill line
    lr_probs = lr_probs[:, 1]
    # calculate scores
    ns_auc = roc_auc_score(y_test, ns_probs)
    lr_auc = roc_auc_score(y_test, lr_probs)
    # summarize scores
    aucns=ns_auc
    auclr=lr_auc
    # TPR FPR
    ns_fpr, ns_tpr, _ = roc_curve(y_test, ns_probs)
    lr_fpr, lr_tpr, _ = roc_curve(y_test, lr_probs)
    tpr=lr_tpr
    fpr=lr_fpr
        
    no_skill = len(y_test[y_test==1]) / len(y_test)#to draw prec recall curve(noskill line)

        
print('No Skill: ROC AUC=%.3f' % (aucns))
print('Bagging: ROC AUC=%.3f' % (auclr))        
# plot the roc curve for the model
plt.plot(ns_fpr, ns_tpr, linestyle='--', label='No Skill')
plt.plot(lr_fpr, lr_tpr, marker='.', label='Bagging')
# axis labels
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
# show the legend
plt.legend()
# show the plot
plt.show()        

column_names2 = ["TPR","FPR"]
dfres2 = pd.DataFrame(columns = column_names2)
dfres2["TPR"]=tpr
dfres2["FPR"]=fpr

column_names3 = [ "Acc"]
dfres3 = pd.DataFrame([results.mean()],columns = column_names3)


# In[156]:


dfres3


# In[695]:


dfres2


# In[696]:


##find the biggest dif,,we want big diff btw fpr and tpr, not want only to have low fp or tp
##If there is no external concern about low TPR or high FPR, one option is to weight them equally
arr=tpr-fpr
maxElement = np.amax(arr)
result = np.where(arr == maxElement)#index of max diff
print(arr)
print(result)
maxElement


# ### 1.f bagging(DT as base) with rfe 150 components

# ##### grid search for base

# In[151]:


from sklearn.model_selection  import train_test_split
X=rfe(150)#traindata
Y=df_up_train.type

X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.4, random_state=4)


nb_classifier = DecisionTreeClassifier()

params_NB = {'criterion' : ['gini', 'entropy'],
            'max_depth' : [2,4,6,8,10,12,20,25,18]
             ,'max_features':[2,4,6,8,10,12,20,25,18]
            }
gs_NB = GridSearchCV(estimator=nb_classifier, 
                 param_grid=params_NB, 
                  # use any cross validation technique 
                 verbose=1, 
                 scoring='accuracy') 
gs_NB.fit(X_train, y_train)

gs_NB.best_params_


# In[152]:


from sklearn.model_selection import RepeatedKFold
results=0
seed = 8
kfold=RepeatedKFold(n_splits=3, n_repeats=2, random_state=1)  
acc,tpr,fpr,aucns,auclr =0,0,0,0,0
model=0
# initialize the base classifier 
base_cls =DecisionTreeClassifier(criterion='entropy',max_depth=20,max_features=25)
#base is used with bagging
for train_index, test_index in kfold.split(X, Y):
    
    X_train, X_test = X.loc[train_index], X.loc[test_index]
    y_train, y_test = Y[train_index], Y[test_index] 
    # bagging classifier 
    model = BaggingClassifier(base_estimator = base_cls,
                             n_estimators=15, 
                              random_state = seed )
    model.fit(X_train, y_train)
    yhat = model.predict(X_test)
    probs = model.predict_proba(X_test)
    probs = probs[:,1]#take the first column for probs
     


    #find acc of model
    results = model_selection.cross_val_score(model, X_test, y_test, cv = kfold)
    

    
    auc = roc_auc_score(y_test, probs)
        
    ns_probs = [0 for _ in range(len(y_test))]#to find no skill probs
    lr_probs = model.predict_proba(X_test)
    # keep probabilities for the positive outcome only,coz that draws the curve below noskill line
    lr_probs = lr_probs[:, 1]
    # calculate scores
    ns_auc = roc_auc_score(y_test, ns_probs)
    lr_auc = roc_auc_score(y_test, lr_probs)
    # summarize scores
    aucns=ns_auc
    auclr=lr_auc
    # TPR FPR
    ns_fpr, ns_tpr, _ = roc_curve(y_test, ns_probs)
    lr_fpr, lr_tpr, _ = roc_curve(y_test, lr_probs)
    tpr=lr_tpr
    fpr=lr_fpr
        
    no_skill = len(y_test[y_test==1]) / len(y_test)#to draw prec recall curve(noskill line)

        
print('No Skill: ROC AUC=%.3f' % (aucns))
print('Bagging: ROC AUC=%.3f' % (auclr))        
# plot the roc curve for the model
plt.plot(ns_fpr, ns_tpr, linestyle='--', label='No Skill')
plt.plot(lr_fpr, lr_tpr, marker='.', label='Bagging')
# axis labels
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
# show the legend
plt.legend()
# show the plot
plt.show()        

column_names2 = ["TPR","FPR"]
dfres2 = pd.DataFrame(columns = column_names2)
dfres2["TPR"]=tpr
dfres2["FPR"]=fpr

column_names3 = [ "Acc"]
dfres3 = pd.DataFrame([results.mean()],columns = column_names3)


# In[699]:


dfres2


# In[700]:


##find the biggest dif,,we want big diff btw fpr and tpr, not want only to have low fp or tp
##If there is no external concern about low TPR or high FPR, one option is to weight them equally
arr=tpr-fpr
maxElement = np.amax(arr)
result = np.where(arr == maxElement)#index of max diff
print(arr)
print(result)
maxElement


# In[153]:


dfres3


# ### 1.g bagging(DT as base) with pca 150 components

# ##### grid search for base

# In[702]:


from sklearn.model_selection  import train_test_split
#X=rfe(150)#traindata
#Y=df_up_train.type
X=df_up_train.drop(columns=['apk','type'])#traindata
pca = PCA( 150)
X =  pca.fit_transform(X)  
Y=df_up_train.type

X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.4, random_state=4)


nb_classifier = DecisionTreeClassifier()

params_NB = {'criterion' : ['gini', 'entropy'],
            'max_depth' : [2,4,6,8,10,12,20,25,18]
             ,'max_features':[2,4,6,8,10,12,20,25,18]
            }
gs_NB = GridSearchCV(estimator=nb_classifier, 
                 param_grid=params_NB, 
                  # use any cross validation technique 
                 verbose=1, 
                 scoring='accuracy') 
gs_NB.fit(X_train, y_train)

gs_NB.best_params_


# In[703]:


seed = 8
results=0
kfold=RepeatedStratifiedKFold(n_splits=3, n_repeats=2, random_state=1)  
acc,tpr,fpr,aucns,auclr =0,0,0,0,0
model=0
# initialize the base classifier 
base_cls =DecisionTreeClassifier(criterion='entropy',max_depth=20,max_features=25)
#base is used with bagging


for train_index, test_index in kfold.split(X, Y):
    
    X_train, X_test = X[train_index], X[test_index]
    y_train, y_test = Y[train_index], Y[test_index] 

    

    # bagging classifier 
    model = BaggingClassifier(base_estimator = base_cls,
                             n_estimators=15, 
                              random_state = seed )
    model.fit(X_train, y_train)
    yhat = model.predict(X_test)
     

 
    
    probs = model.predict_proba(X_test)
    probs = probs[:,1]#take the first column for probs
     


    #find acc of model
    results = model_selection.cross_val_score(model, X_test, y_test, cv = kfold)
    

    
    auc = roc_auc_score(y_test, probs)
        
    ns_probs = [0 for _ in range(len(y_test))]#to find no skill probs
    lr_probs = model.predict_proba(X_test)
    # keep probabilities for the positive outcome only,coz that draws the curve below noskill line
    lr_probs = lr_probs[:, 1]
    # calculate scores
    ns_auc = roc_auc_score(y_test, ns_probs)
    lr_auc = roc_auc_score(y_test, lr_probs)
    # summarize scores
    aucns=ns_auc
    auclr=lr_auc
    # TPR FPR
    ns_fpr, ns_tpr, _ = roc_curve(y_test, ns_probs)
    lr_fpr, lr_tpr, _ = roc_curve(y_test, lr_probs)
    tpr=lr_tpr
    fpr=lr_fpr
        
    no_skill = len(y_test[y_test==1]) / len(y_test)#to draw prec recall curve(noskill line)

        
print('No Skill: ROC AUC=%.3f' % (aucns))
print('Bagging: ROC AUC=%.3f' % (auclr))        
# plot the roc curve for the model
plt.plot(ns_fpr, ns_tpr, linestyle='--', label='No Skill')
plt.plot(lr_fpr, lr_tpr, marker='.', label='Bagging')
# axis labels
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
# show the legend
plt.legend()
# show the plot
plt.show()        

column_names2 = ["TPR","FPR"]
dfres2 = pd.DataFrame(columns = column_names2)
dfres2["TPR"]=tpr
dfres2["FPR"]=fpr

column_names3 = [ "Acc"]
dfres3 = pd.DataFrame([results.mean()],columns = column_names3)


# In[704]:


dfres2


# In[705]:


##find the biggest dif,,we want big diff btw fpr and tpr, not want only to have low fp or tp
##If there is no external concern about low TPR or high FPR, one option is to weight them equally
arr=tpr-fpr
maxElement = np.amax(arr)
result = np.where(arr == maxElement)#index of max diff
print(arr)
print(result)
maxElement


# In[706]:


dfres3


# ### 1.h bagging(DT as base) with pca 20 components

# ##### grid search for base

# In[707]:


from sklearn.model_selection  import train_test_split
#X=rfe(150)#traindata
#Y=df_up_train.type
X=df_up_train.drop(columns=['apk','type'])#traindata
pca = PCA( 20)
X =  pca.fit_transform(X)  
Y=df_up_train.type

X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.4, random_state=4)


nb_classifier = DecisionTreeClassifier()

params_NB = {'criterion' : ['gini', 'entropy'],
            'max_depth' : [2,4,6,8,10,12,20,25,18]
             ,'max_features':[2,4,6,8,10,12,20,25,18]
            }
gs_NB = GridSearchCV(estimator=nb_classifier, 
                 param_grid=params_NB, 
                  # use any cross validation technique 
                 verbose=1, 
                 scoring='accuracy') 
gs_NB.fit(X_train, y_train)

gs_NB.best_params_


# In[708]:


results=0
seed = 8

kfold=RepeatedStratifiedKFold(n_splits=3, n_repeats=2, random_state=1)  
acc,tpr,fpr,aucns,auclr =0,0,0,0,0
model=0
# initialize the base classifier 
base_cls =DecisionTreeClassifier(criterion='entropy',max_depth=18,max_features=18)
#base is used with bagging


for train_index, test_index in kfold.split(X, Y):
    
    X_train, X_test = X[train_index], X[test_index]
    y_train, y_test = Y[train_index], Y[test_index] 

    

    # bagging classifier 
    model = BaggingClassifier(base_estimator = base_cls,
                             n_estimators=15, 
                              random_state = seed )
    model.fit(X_train, y_train)
    yhat = model.predict(X_test)
     

 
    
    probs = model.predict_proba(X_test)
    probs = probs[:,1]#take the first column for probs
     


    #find acc of model
    results = model_selection.cross_val_score(model, X_test, y_test, cv = kfold)
    

    
    auc = roc_auc_score(y_test, probs)
        
    ns_probs = [0 for _ in range(len(y_test))]#to find no skill probs
    lr_probs = model.predict_proba(X_test)
    # keep probabilities for the positive outcome only,coz that draws the curve below noskill line
    lr_probs = lr_probs[:, 1]
    # calculate scores
    ns_auc = roc_auc_score(y_test, ns_probs)
    lr_auc = roc_auc_score(y_test, lr_probs)
    # summarize scores
    aucns=ns_auc
    auclr=lr_auc
    # TPR FPR
    ns_fpr, ns_tpr, _ = roc_curve(y_test, ns_probs)
    lr_fpr, lr_tpr, _ = roc_curve(y_test, lr_probs)
    tpr=lr_tpr
    fpr=lr_fpr
        
    no_skill = len(y_test[y_test==1]) / len(y_test)#to draw prec recall curve(noskill line)

        
print('No Skill: ROC AUC=%.3f' % (aucns))
print('Bagging: ROC AUC=%.3f' % (auclr))        
# plot the roc curve for the model
plt.plot(ns_fpr, ns_tpr, linestyle='--', label='No Skill')
plt.plot(lr_fpr, lr_tpr, marker='.', label='Bagging')
# axis labels
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
# show the legend
plt.legend()
# show the plot
plt.show()        

column_names2 = ["TPR","FPR"]
dfres2 = pd.DataFrame(columns = column_names2)
dfres2["TPR"]=tpr
dfres2["FPR"]=fpr

column_names3 = [ "Acc"]
dfres3 = pd.DataFrame([results.mean()],columns = column_names3)


# In[709]:


dfres2


# In[710]:


##find the biggest dif,,we want big diff btw fpr and tpr, not want only to have low fp or tp
##If there is no external concern about low TPR or high FPR, one option is to weight them equally
arr=tpr-fpr
maxElement = np.amax(arr)
result = np.where(arr == maxElement)#index of max diff
print(arr)
print(result)
maxElement


# In[711]:


dfres3


# ## 2.adaboosting

# ### 2.a adaboosting(DT as base default) with pca20 components

# In[139]:


X=df_up_train.drop(columns=['apk','type'])#traindata
y=df_up_train.type
pca = PCA( 20)
X =  pca.fit_transform(X)  
Y=df_up_train.type
seed = 8
results=0
kfold=RepeatedStratifiedKFold(n_splits=3, n_repeats=2, random_state=1)  
acc,tpr,fpr,aucns,auclr =0,0,0,0,0
model=0
# initialize the base classifier 
#base_cls =DecisionTreeClassifier(max_features=18)
#base is used with bagging


for train_index, test_index in kfold.split(X, Y):
    
    X_train, X_test = X[train_index], X[test_index]
    y_train, y_test = Y[train_index], Y[test_index] 

    

    # bagging classifier 
    model =  model = AdaBoostClassifier()
    model.fit(X_train, y_train)
    yhat = model.predict(X_test)
     

 
    
    probs = model.predict_proba(X_test)
    probs = probs[:,1]#take the first column for probs
     


    #find acc of model
    results = model_selection.cross_val_score(model, X_test, y_test, cv = kfold)
    

    
    auc = roc_auc_score(y_test, probs)
        
    ns_probs = [0 for _ in range(len(y_test))]#to find no skill probs
    lr_probs = model.predict_proba(X_test)
    # keep probabilities for the positive outcome only,coz that draws the curve below noskill line
    lr_probs = lr_probs[:, 1]
    # calculate scores
    ns_auc = roc_auc_score(y_test, ns_probs)
    lr_auc = roc_auc_score(y_test, lr_probs)
    # summarize scores
    aucns=ns_auc
    auclr=lr_auc
    # TPR FPR
    ns_fpr, ns_tpr, _ = roc_curve(y_test, ns_probs)
    lr_fpr, lr_tpr, _ = roc_curve(y_test, lr_probs)
    tpr=lr_tpr
    fpr=lr_fpr
        
    no_skill = len(y_test[y_test==1]) / len(y_test)#to draw prec recall curve(noskill line)




        
        
print('No Skill: ROC AUC=%.3f' % (aucns))
print('Bagging: ROC AUC=%.3f' % (auclr))        
# plot the roc curve for the model
plt.plot(ns_fpr, ns_tpr, linestyle='--', label='No Skill')
plt.plot(lr_fpr, lr_tpr, marker='.', label='ada')
# axis labels
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
# show the legend
plt.legend()
# show the plot
plt.show()        



column_names2 = ["TPR","FPR"]
dfres2 = pd.DataFrame(columns = column_names2)
dfres2["TPR"]=tpr
dfres2["FPR"]=fpr

column_names3 = [ "Acc"]
dfres3 = pd.DataFrame([   results.mean()],columns = column_names3)


# In[652]:


dfres2


# ### 

# In[140]:


dfres3


# ### 2.b adaboosting(DT as base default) with pca 150 components

# In[648]:


X=df_up_train.drop(columns=['apk','type'])#traindata
y=df_up_train.type
pca = PCA( 150)
X =  pca.fit_transform(X)  
Y=df_up_train.type
seed = 8
results=0
kfold=RepeatedStratifiedKFold(n_splits=3, n_repeats=2, random_state=1)  
acc,tpr,fpr,aucns,auclr =0,0,0,0,0
model=0
# initialize the base classifier 
#base_cls =DecisionTreeClassifier(max_features=18)
#base is used with bagging


for train_index, test_index in kfold.split(X, Y):
    
    X_train, X_test = X[train_index], X[test_index]
    y_train, y_test = Y[train_index], Y[test_index] 

    

    # bagging classifier 
    model =  model = AdaBoostClassifier()
    model.fit(X_train, y_train)
    yhat = model.predict(X_test)
     

 
    
    probs = model.predict_proba(X_test)
    probs = probs[:,1]#take the first column for probs
     


    #find acc of model
    results = model_selection.cross_val_score(model, X_test, y_test, cv = kfold)
    

    
    auc = roc_auc_score(y_test, probs)
        
    ns_probs = [0 for _ in range(len(y_test))]#to find no skill probs
    lr_probs = model.predict_proba(X_test)
    # keep probabilities for the positive outcome only,coz that draws the curve below noskill line
    lr_probs = lr_probs[:, 1]
    # calculate scores
    ns_auc = roc_auc_score(y_test, ns_probs)
    lr_auc = roc_auc_score(y_test, lr_probs)
    # summarize scores
    aucns=ns_auc
    auclr=lr_auc
    # TPR FPR
    ns_fpr, ns_tpr, _ = roc_curve(y_test, ns_probs)
    lr_fpr, lr_tpr, _ = roc_curve(y_test, lr_probs)
    tpr=lr_tpr
    fpr=lr_fpr
        
    no_skill = len(y_test[y_test==1]) / len(y_test)#to draw prec recall curve(noskill line)




        
        
print('No Skill: ROC AUC=%.3f' % (aucns))
print('Bagging: ROC AUC=%.3f' % (auclr))        
# plot the roc curve for the model
plt.plot(ns_fpr, ns_tpr, linestyle='--', label='No Skill')
plt.plot(lr_fpr, lr_tpr, marker='.', label='ada')
# axis labels
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
# show the legend
plt.legend()
# show the plot
plt.show()        



column_names2 = ["TPR","FPR"]
dfres2 = pd.DataFrame(columns = column_names2)
dfres2["TPR"]=tpr
dfres2["FPR"]=fpr

column_names3 = [ "Acc"]
dfres3 = pd.DataFrame([   results.mean()],columns = column_names3)


# In[649]:


dfres2


# In[650]:


dfres3


# ### 2.c adaboosting(DT as base default) with rfe 150 components

# In[639]:


X=rfe(150)#traindata
Y=df_up_train.type
seed = 8
results=0
kfold=RepeatedStratifiedKFold(n_splits=3, n_repeats=2, random_state=1)  
acc,tpr,fpr,aucns,auclr =0,0,0,0,0
model=0
# initialize the base classifier 
base_cls =DecisionTreeClassifier(max_features=18)
#base is used with bagging


for train_index, test_index in kfold.split(X, Y):
    
    X_train, X_test = X.loc[train_index], X.loc[test_index]
    y_train, y_test = Y[train_index], Y[test_index] 

    

    # bagging classifier 
    model =  model = AdaBoostClassifier(base_estimator = base_cls)
    model.fit(X_train, y_train)
    yhat = model.predict(X_test)
     

 
    
    probs = model.predict_proba(X_test)
    probs = probs[:,1]#take the first column for probs
     


    #find acc of model
    results = model_selection.cross_val_score(model, X_test, y_test, cv = kfold)
    

    


    auc = roc_auc_score(y_test, probs)
        
    ns_probs = [0 for _ in range(len(y_test))]#to find no skill probs
    lr_probs = model.predict_proba(X_test)
    # keep probabilities for the positive outcome only,coz that draws the curve below noskill line
    lr_probs = lr_probs[:, 1]
    # calculate scores
    ns_auc = roc_auc_score(y_test, ns_probs)
    lr_auc = roc_auc_score(y_test, lr_probs)
    # summarize scores
    aucns=ns_auc
    auclr=lr_auc
    # TPR FPR
    ns_fpr, ns_tpr, _ = roc_curve(y_test, ns_probs)
    lr_fpr, lr_tpr, _ = roc_curve(y_test, lr_probs)
    tpr=lr_tpr
    fpr=lr_fpr
        
    no_skill = len(y_test[y_test==1]) / len(y_test)#to draw prec recall curve(noskill line)




        
        
print('No Skill: ROC AUC=%.3f' % (aucns))
print('Bagging: ROC AUC=%.3f' % (auclr))        
# plot the roc curve for the model
plt.plot(ns_fpr, ns_tpr, linestyle='--', label='No Skill')
plt.plot(lr_fpr, lr_tpr, marker='.', label='Bagging')
# axis labels
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
# show the legend
plt.legend()
# show the plot
plt.show()        



column_names2 = ["TPR","FPR"]
dfres2 = pd.DataFrame(columns = column_names2)
dfres2["TPR"]=tpr
dfres2["FPR"]=fpr

column_names3 = [ "Acc"]
dfres3 = pd.DataFrame([ results.mean()],columns = column_names3)


# In[615]:


dfres2


# In[640]:


dfres3


# In[617]:


##find the biggest dif,,we want big diff btw fpr and tpr, not want only to have low fp or tp
##If there is no external concern about low TPR or high FPR, one option is to weight them equally
arr=tpr-fpr
maxElement = np.amax(arr)
result = np.where(arr == maxElement)#index of max diff
print(arr)
print(result)
maxElement


# ### 1.L adaboosting(DT as base default) with rfe 170 components

# In[645]:


X=rfe(170)#traindata
Y=df_up_train.type
seed = 8
results=0
kfold=RepeatedStratifiedKFold(n_splits=3, n_repeats=2, random_state=1)  
acc,tpr,fpr,aucns,auclr =0,0,0,0,0
model=0
# initialize the base classifier 
base_cls =DecisionTreeClassifier(max_features=18)
#base is used with bagging


for train_index, test_index in kfold.split(X, Y):
    
    X_train, X_test = X.loc[train_index], X.loc[test_index]
    y_train, y_test = Y[train_index], Y[test_index] 

    

    # bagging classifier 
    model  = AdaBoostClassifier(base_estimator = base_cls)
    model.fit(X_train, y_train)
    yhat = model.predict(X_test)
     

 
    
    probs = model.predict_proba(X_test)
    probs = probs[:,1]#take the first column for probs
     


    #find acc of model
    results = model_selection.cross_val_score(model, X_test, y_test, cv = kfold)
    
 

    auc = roc_auc_score(y_test, probs)
        
    ns_probs = [0 for _ in range(len(y_test))]#to find no skill probs
    lr_probs = model.predict_proba(X_test)
    # keep probabilities for the positive outcome only,coz that draws the curve below noskill line
    lr_probs = lr_probs[:, 1]
    # calculate scores
    ns_auc = roc_auc_score(y_test, ns_probs)
    lr_auc = roc_auc_score(y_test, lr_probs)
    # summarize scores
    aucns=ns_auc
    auclr=lr_auc
    # TPR FPR
    ns_fpr, ns_tpr, _ = roc_curve(y_test, ns_probs)
    lr_fpr, lr_tpr, _ = roc_curve(y_test, lr_probs)
    tpr=lr_tpr
    fpr=lr_fpr
        
    no_skill = len(y_test[y_test==1]) / len(y_test)#to draw prec recall curve(noskill line)




        
        
print('No Skill: ROC AUC=%.3f' % (aucns))
print('Bagging: ROC AUC=%.3f' % (auclr))        
# plot the roc curve for the model
plt.plot(ns_fpr, ns_tpr, linestyle='--', label='No Skill')
plt.plot(lr_fpr, lr_tpr, marker='.', label='ada')
# axis labels
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
# show the legend
plt.legend()
# show the plot
plt.show()        



column_names2 = ["TPR","FPR"]
dfres2 = pd.DataFrame(columns = column_names2)
dfres2["TPR"]=tpr
dfres2["FPR"]=fpr

column_names3 = [ "Acc"]
dfres3 = pd.DataFrame([   results.mean()],columns = column_names3)


# In[646]:


dfres2


# In[647]:


dfres3


# ## 3. lightgbm

# In[171]:


X=rfe(150)#traindata
Y=df_up_train.type
seed = 8

kfold=RepeatedStratifiedKFold(n_splits=3, n_repeats=2, random_state=1)  
acc,tpr,fpr,aucns,auclr =0,0,0,0,0
model=0
# initialize the base classifier 
results=0

for train_index, test_index in kfold.split(X, Y):
    
    X_train, X_test = X.loc[train_index], X.loc[test_index]
    y_train, y_test = Y[train_index], Y[test_index] 

    

    # bagging classifier 
    model  = lgb.LGBMClassifier(learning_rate = 0.01, metric = 'l1', 
                       num_leaves=10,
                         n_estimators=10,
                         max_bin = 55, bagging_fraction = 0.8,  bagging_freq = 5, feature_fraction = 0.2319,
                         feature_fraction_seed=9, bagging_seed=9,
                         min_data_in_leaf =6, min_sum_hessian_in_leaf = 11)
    model.fit(X_train, y_train)
    yhat = model.predict(X_test)
     

 
    
    probs = model.predict_proba(X_test)
    probs = probs[:,1]#take the first column for probs
     


    #find acc of model
    results = model_selection.cross_val_score(model, X_test, y_test, cv = kfold)
    #results is array of all acc

    
 
    auc = roc_auc_score(y_test, probs)
        
    ns_probs = [0 for _ in range(len(y_test))]#to find no skill probs
    lr_probs = model.predict_proba(X_test)
    # keep probabilities for the positive outcome only,coz that draws the curve below noskill line
    lr_probs = lr_probs[:, 1]
    # calculate scores
    ns_auc = roc_auc_score(y_test, ns_probs)
    lr_auc = roc_auc_score(y_test, lr_probs)
    # summarize scores
    aucns=ns_auc
    auclr=lr_auc
    # TPR FPR
    ns_fpr, ns_tpr, _ = roc_curve(y_test, ns_probs)
    lr_fpr, lr_tpr, _ = roc_curve(y_test, lr_probs)
    tpr=lr_tpr
    fpr=lr_fpr
        
    no_skill = len(y_test[y_test==1]) / len(y_test)#to draw prec recall curve(noskill line)




        
        
print('No Skill: ROC AUC=%.3f' % (aucns))
print('Bagging: ROC AUC=%.3f' % (auclr))        
# plot the roc curve for the model
plt.plot(ns_fpr, ns_tpr, linestyle='--', label='No Skill')
plt.plot(lr_fpr, lr_tpr, marker='.', label='ada')
# axis labels
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
# show the legend
plt.legend()
# show the plot
plt.show()        



column_names2 = ["TPR","FPR"]
dfres2 = pd.DataFrame(columns = column_names2)
dfres2["TPR"]=tpr
dfres2["FPR"]=fpr

column_names3 = [ "Acc"]
dfres3 = pd.DataFrame([   results.mean()],columns = column_names3)


# In[172]:


dfres3


# In[727]:


dfres2


# In[728]:


##find the biggest dif,,we want big diff btw fpr and tpr, not want only to have low fp or tp
##If there is no external concern about low TPR or high FPR, one option is to weight them equally
arr=tpr-fpr
maxElement = np.amax(arr)
result = np.where(arr == maxElement)#index of max diff
print(arr)
print(result)
maxElement

