import subprocess
import numpy as np

runTimes = 100

senderL = np.zeros(runTimes)
hubL = np.zeros(runTimes)
receiverL = np.zeros(runTimes)
auditorL = np.zeros(runTimes)

sender = np.zeros(runTimes)
hub = np.zeros(runTimes)
receiver = np.zeros(runTimes)

for i in range(runTimes):
    resL = subprocess.check_output('./EXP2', shell=True)
    resL = resL.decode('utf-8')
    resL_split = resL.splitlines()

    sender_timeL = eval(resL_split[0][-11:-4])
    hub_timeL = eval(resL_split[2][-11:-4])
    receiver_timeL = eval(resL_split[4][-11:-4])
    auditor_timeL = eval(resL_split[6][-11:-4])

    senderL[i] = sender_timeL
    hubL[i] = hub_timeL
    receiverL[i] = receiver_timeL
    auditorL[i] = auditor_timeL

    res = subprocess.check_output('./RSUCEXP2', shell=True)
    res = res.decode('utf-8')
    res_split = res.splitlines()

    sender_time = eval(res_split[0][-11:-4])
    hub_time = eval(res_split[2][-11:-4])
    receiver_time = eval(res_split[4][-11:-4])

    sender[i] = sender_time
    hub[i] = hub_time
    receiver[i] = receiver_time

print("Sender time AVG: {:.5f} sec".format(np.mean(senderL)))
print("Hub time AVG: {:.5f} sec".format(np.mean(hubL)))
print("Receiver time AVG: {:.5f} sec".format(np.mean(receiverL)))
print("Auditor time AVG: {:.5f} sec".format(np.mean(auditorL)))

print("Sender time AVG: {:.5f} sec".format(np.mean(sender)))
print("Hub time AVG: {:.5f} sec".format(np.mean(hub)))
print("Receiver time AVG: {:.5f} sec".format(np.mean(receiver)))
