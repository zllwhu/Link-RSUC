import subprocess
import numpy as np

runTimes = 100

setup = np.zeros(runTimes)
keyGen = np.zeros(runTimes)
authCom = np.zeros(runTimes)
vfCom = np.zeros(runTimes)
vfAuth = np.zeros(runTimes)
rdmAC = np.zeros(runTimes)
vfProof = np.zeros(runTimes)
updAC = np.zeros(runTimes)
vfUpd = np.zeros(runTimes)

for i in range(runTimes):
    res = subprocess.check_output('./LinkRSUC', shell=True)
    res = res.decode('utf-8')
    res_split = res.splitlines()

    setup_time = eval(res_split[0][-11:-4])
    keyGen_time = eval(res_split[2][-11:-4])
    authCom_time = eval(res_split[4][-11:-4])
    vfCom_time = eval(res_split[6][-11:-4])
    vfAuth_time = eval(res_split[8][-11:-4])
    rdmAC_time = eval(res_split[10][-11:-4])
    vfProof_time = eval(res_split[12][-11:-4])
    updAC_time = eval(res_split[14][-11:-4])
    vfUpd_time = eval(res_split[16][-11:-4])

    setup[i] = setup_time
    keyGen[i] = keyGen_time
    authCom[i] = authCom_time
    vfCom[i] = vfCom_time
    vfAuth[i] = vfAuth_time
    rdmAC[i] = rdmAC_time
    vfProof[i] = vfProof_time
    updAC[i] = updAC_time
    vfUpd[i] = vfUpd_time

print("Setup time AVG: {:.5f} sec".format(np.mean(setup)))
print("KeyGen time AVG: {:.5f} sec".format(np.mean(keyGen)))
print("AuthCom time AVG: {:.5f} sec".format(np.mean(authCom)))
print("VfCom time AVG: {:.5f} sec".format(np.mean(vfCom)))
print("VfAuth time AVG: {:.5f} sec".format(np.mean(vfAuth)))
print("RdmAC time AVG: {:.5f} sec".format(np.mean(rdmAC)))
print("VfProof time AVG: {:.5f} sec".format(np.mean(vfProof)))
print("UpdAC time AVG: {:.5f} sec".format(np.mean(updAC)))
print("VfUpd time AVG: {:.5f} sec".format(np.mean(vfUpd)))
