#!/usr/bin/env python3
import time
import serial
import sys

class SBuf:
    def __init__(self, fout):
        self.b = bytearray()
        self.f = fout
        self.output = False

    def feed(self, d):
        print('F')
        t = []

        for i in range(0,len(d)):
            t.append(d[i])
            if d[i] == 0x7E:
                if self.output:
                    self.b += bytes(t)
                    self.f.write(self.b)
                    self.b = bytes()
                    t = []
                    print('Out')
                else:
                    self.output = True
                    print('Start')
        if len(t) > 0:
            self.b += bytes(t)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Error: Usage ./collect.py PORT BAUDRATE OUTPUT.')
        sys.exit(-1)

    serial_in = serial.Serial(sys.argv[1], baudrate=int(sys.argv[2]),
                              timeout=None, rtscts=True, dsrdtr=True)
    fout = open("board-" + str(int(time.time())) + "-" + sys.argv[3] + ".qmdl", 'wb')
    sbuf = SBuf(fout)

    try:
        while True:
            try:
                s = serial_in.read(64)
                sbuf.feed(s)
            except (KeyboardInterrupt) as e:
                print('\n\n%s Detected: Quitting' % type(e).__name__)
                fout.close()
                sys.exit(e)
            except:
                print('\nReading Error')
                time.sleep(0.5)
                serial_in = serial.Serial(sys.argv[1], baudrate=int(sys.argv[2]), timeout=None, rtscts=True, dsrdtr=True)
                time.sleep(0.5)

    except (KeyboardInterrupt, RuntimeError) as e:
        print('\n\n%s Detected: Quitting' % type(e).__name__)
        fout.close()
        sys.exit(e)

