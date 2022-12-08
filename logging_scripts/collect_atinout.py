import subprocess, time

output = subprocess.check_output('echo \'AT#MONI=7\' | sudo atinout - /dev/ttyUSB2 -', shell=True, text=True)
print(output)

logfile = open("./logs/at_trace_"+str(int(time.time()))+".txt", "w")

def process_msg(msg):
    msg = msg.split("\n")
    msg = [m for m in msg if len(m) > 5]
    print(msg)
    for m in msg:
        print(curTime, m)
        logfile.write(str(curTime) + " " + m + "\n")
while True:
    try:
        curTime = time.time()
        output = subprocess.check_output('echo \'AT#RFSTS\' | sudo atinout - /dev/ttyUSB2 -', shell=True, text=True)
        process_msg(output)

        time.sleep(0.1)

        curTime = time.time()
        output = subprocess.check_output('echo \'AT#MONI\' | sudo atinout - /dev/ttyUSB2 -', shell=True, text=True)
        process_msg(output)

        time.sleep(0.1)

        curTime = time.time()
        output = subprocess.check_output('echo \'AT+CREG?\' | sudo atinout - /dev/ttyUSB2 -', shell=True, text=True)
        process_msg(output)

        time.sleep(0.1)

        curTime = time.time()
        output = subprocess.check_output('echo \'AT+CGATT=1\' | sudo atinout - /dev/ttyUSB2 -', shell=True, text=True)
        process_msg(output)

        time.sleep(0.1)

        curTime = time.time()
        output = subprocess.check_output('echo \'AT+CGACT=1\' | sudo atinout - /dev/ttyUSB2 -', shell=True, text=True)
        process_msg(output)

        time.sleep(0.1)
    
        curTime = time.time()
        output = subprocess.check_output('echo \'AT#SGACT=1,1\' | sudo atinout - /dev/ttyUSB2 -', shell=True, text=True)
        process_msg(output)

        time.sleep(0.1)

        curTime = time.time()
        output = subprocess.check_output('echo \'AT#PING=8.8.8.8,1\' | sudo atinout - /dev/ttyUSB2 -', shell=True, text=True)
        process_msg(output)

        time.sleep(1)
    except:
        time.sleep(0.1)
