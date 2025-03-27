import subprocess
import numpy as np

runTimes = 100

setupL = np.zeros(runTimes)
keyGenL = np.zeros(runTimes)
authComL = np.zeros(runTimes)
vfComL = np.zeros(runTimes)
vfAuthL = np.zeros(runTimes)
rdmACL = np.zeros(runTimes)
vfProofL = np.zeros(runTimes)
updACL = np.zeros(runTimes)
vfUpdL = np.zeros(runTimes)
linkCPL = np.zeros(runTimes)

setup = np.zeros(runTimes)
keyGen = np.zeros(runTimes)
authCom = np.zeros(runTimes)
vfCom = np.zeros(runTimes)
vfAuth = np.zeros(runTimes)
rdmAC = np.zeros(runTimes)
updAC = np.zeros(runTimes)
vfUpd = np.zeros(runTimes)

for i in range(runTimes):
    resL = subprocess.check_output('./EXP1', shell=True)
    resL = resL.decode('utf-8')
    resL_split = resL.splitlines()

    setup_timeL = eval(resL_split[0][-11:-4])
    keyGen_timeL = eval(resL_split[2][-11:-4])
    authCom_timeL = eval(resL_split[4][-11:-4])
    vfCom_timeL = eval(resL_split[6][-11:-4])
    vfAuth_timeL = eval(resL_split[8][-11:-4])
    rdmAC_timeL = eval(resL_split[10][-11:-4])
    vfProof_timeL = eval(resL_split[12][-11:-4])
    updAC_timeL = eval(resL_split[14][-11:-4])
    vfUpd_timeL = eval(resL_split[16][-11:-4])
    linkCP_timeL = eval(resL_split[18][-11:-4])

    setupL[i] = setup_timeL
    keyGenL[i] = keyGen_timeL
    authComL[i] = authCom_timeL
    vfComL[i] = vfCom_timeL
    vfAuthL[i] = vfAuth_timeL
    rdmACL[i] = rdmAC_timeL
    vfProofL[i] = vfProof_timeL
    updACL[i] = updAC_timeL
    vfUpdL[i] = vfUpd_timeL
    linkCPL[i] = linkCP_timeL

    res = subprocess.check_output('./RSUCEXP1', shell=True)
    res = res.decode('utf-8')
    res_split = res.splitlines()

    setup_time = eval(res_split[0][-11:-4])
    keyGen_time = eval(res_split[2][-11:-4])
    authCom_time = eval(res_split[4][-11:-4])
    vfCom_time = eval(res_split[6][-11:-4])
    vfAuth_time = eval(res_split[8][-11:-4])
    rdmAC_time = eval(res_split[10][-11:-4])
    updAC_time = eval(res_split[12][-11:-4])
    vfUpd_time = eval(res_split[14][-11:-4])

    setup[i] = setup_time
    keyGen[i] = keyGen_time
    authCom[i] = authCom_time
    vfCom[i] = vfCom_time
    vfAuth[i] = vfAuth_time
    rdmAC[i] = rdmAC_time
    updAC[i] = updAC_time
    vfUpd[i] = vfUpd_time

print("Setup time AVG: {:.5f} sec".format(np.mean(setupL)))
print("KeyGen time AVG: {:.5f} sec".format(np.mean(keyGenL)))
print("AuthCom time AVG: {:.5f} sec".format(np.mean(authComL)))
print("VfCom time AVG: {:.5f} sec".format(np.mean(vfComL)))
print("VfAuth time AVG: {:.5f} sec".format(np.mean(vfAuthL)))
print("RdmAC time AVG: {:.5f} sec".format(np.mean(rdmACL)))
print("VfProof time AVG: {:.5f} sec".format(np.mean(vfProofL)))
print("UpdAC time AVG: {:.5f} sec".format(np.mean(updACL)))
print("VfUpd time AVG: {:.5f} sec".format(np.mean(vfUpdL)))
print("LinkCP time AVG: {:.5f} sec".format(np.mean(linkCPL)))

print("Setup time AVG: {:.5f} sec".format(np.mean(setup)))
print("KeyGen time AVG: {:.5f} sec".format(np.mean(keyGen)))
print("AuthCom time AVG: {:.5f} sec".format(np.mean(authCom)))
print("VfCom time AVG: {:.5f} sec".format(np.mean(vfCom)))
print("VfAuth time AVG: {:.5f} sec".format(np.mean(vfAuth)))
print("RdmAC time AVG: {:.5f} sec".format(np.mean(rdmAC)))
print("UpdAC time AVG: {:.5f} sec".format(np.mean(updAC)))
print("VfUpd time AVG: {:.5f} sec".format(np.mean(vfUpd)))
