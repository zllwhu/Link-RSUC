import subprocess
import numpy as np

init = np.zeros(100)
authCom = np.zeros(100)
vfCom = np.zeros(100)
vfAuth = np.zeros(100)
rdmAC = np.zeros(100)
updAC = np.zeros(100)
vfUpd = np.zeros(100)

for i in range(100):
    res = subprocess.check_output('./main', shell=True)
    res = res.decode('utf-8')
    res_split = res.splitlines()

    init_time = eval(res_split[0][-11:-4])
    authCom_time = eval(res_split[2][-11:-4])
    vfCom_time = eval(res_split[4][-11:-4])
    vfAuth_time = eval(res_split[6][-11:-4])
    rdmAC_time = eval(res_split[8][-11:-4])
    updAC_time = eval(res_split[10][-11:-4])
    vfUpd_time = eval(res_split[12][-11:-4])

    init[i] = init_time
    authCom[i] = authCom_time
    vfCom[i] = vfCom_time
    vfAuth[i] = vfAuth_time
    rdmAC[i] = rdmAC_time
    updAC[i] = updAC_time
    vfUpd[i] = vfUpd_time

print("Init time AVG: {:.5f} sec".format(np.mean(init)))
print("AuthCom time AVG: {:.5f} sec".format(np.mean(authCom)))
print("VfCom time AVG: {:.5f} sec".format(np.mean(vfCom)))
print("VfAuth time AVG: {:.5f} sec".format(np.mean(vfAuth)))
print("RdmAC time AVG: {:.5f} sec".format(np.mean(rdmAC)))
print("UpdAC time AVG: {:.5f} sec".format(np.mean(updAC)))
print("VfUpd time AVG: {:.5f} sec".format(np.mean(vfUpd)))
