#!/usr/bin/python
# Filename: buffer_analyzer.py
"""

Analyzer for MAC Buffer & RLC messages

Author: Jinghao Zhao
"""

__all__ = ["BufferAnalyzer"]

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

from mobile_insight.analyzer.analyzer import *
from mobile_insight.analyzer import *
from datetime import datetime
import time
import dis
import re

class BufferAnalyzer(Analyzer):
    """
    An KPI analyzer to monitor and manage uplink latency breakdown
    """
    def __init__(self, path, filename):
        Analyzer.__init__(self)
        self.add_source_callback(self.__msg_callback)


        self.fn = -1
        self.sfn = -1
        self.last_buffer = 0
        self.pkt_size = 40
        self.in_t = -1
        self.latency_list = []
        self.last_t = -1

        # record the fn/sfn round
        self.mac_round = 0
        self.rlc_round = 0
        self.last_fn = 0
        self.rlc_last_fn = 0
        self.sync_count = 0
        self.synced = False

        self.mac_msg = open(path + filename + '_mac.txt', 'w')
        self.rlc_msg = open(path + filename + '_rlc.txt', 'w')
        self.config_msg = open(path + filename + '_config.txt', 'w')
        self.sr_msg = open(path + filename + '_sr.txt', 'w')
        self.all_msg = open(path + filename + '_all.txt', 'w')
        

    def set_source(self, source):
        """
        Set the trace source. Enable the cellular signaling messages

        :param source: the trace source (collector).
        """
        Analyzer.set_source(self, source)

        source.enable_log_all()

    def __f_time_diff(self, t1, t2):
        if t1 > t2:
            t_diff = t2 + 10240 - t1
        else:
            t_diff = t2 - t1
        return t_diff


    def __msg_callback(self, msg):
        # print("ID:",msg.type_id)
        if msg.type_id == "LTE_RRC_CDRX_Events_Info":
            decoded_msg = msg.data.decode()
            timestamp = int(datetime.timestamp(decoded_msg['timestamp']))
            # print(decoded_msg)
            for record in decoded_msg['Records']:
                if record['CDRX Event'] == 'CDRX_OFF_2_ON' :
                    self.config_msg.write("CDRX_OFF_2_ON: %s %s %s\n" % (timestamp,str(record['SFN']),str(record['Sub-FN'])))
                if record['CDRX Event'] == 'CDRX_ON_2_OFF' :
                    self.config_msg.write("CDRX_ON_2_OFF: %s %s %s\n" % (timestamp,str(record['SFN']),str(record['Sub-FN'])))

        elif msg.type_id == "LTE_PHY_PUCCH_Tx_Report":
            decoded_msg = msg.data.decode()
            timestamp = int(datetime.timestamp(decoded_msg['timestamp']))
            for record in decoded_msg['Records']:
                if record['Format'] == 'Format 1':
                    # print("SR:",timestamp,str(record['Current SFN SF'])[:-1],str(record['Current SFN SF'])[-1])
                    self.sr_msg.write("SR: %s %s %s\n" % (timestamp,str(record['Current SFN SF'])[:-1],str(record['Current SFN SF'])[-1]))
                    self.all_msg.write("%s %s %s SR\n" % (timestamp,str(record['Current SFN SF'])[:-1],str(record['Current SFN SF'])[-1]))

        elif msg.type_id == "LTE_MAC_UL_Transport_Block":
            decoded_msg = msg.data.decode()
            timestamp = int(datetime.timestamp(decoded_msg['timestamp']))
            # print(decoded_msg)
            for packet in decoded_msg['Subpackets']:
                for sample in packet['Samples']:
                    padding = sample['Padding (bytes)']
                    grant = sample["Grant (bytes)"]
                    # print("Grant Time:", timestamp, sample['SFN'], sample['Sub-FN'])
                    self.config_msg.write("Grant Time: %s %s %s\n" % (timestamp, str(sample['SFN']), str(sample['Sub-FN'])))
                    self.all_msg.write("%s %s %s Grant %s %s\n" % (timestamp, str(sample['SFN']), str(sample['Sub-FN']), str(grant), str(padding)))
                    res_util = (grant - padding) / grant
                    self.config_msg.write("Grant: %s Padding: %s Util: %s\n" % (str(grant), str(padding), str(res_util)))

        elif msg.type_id == "LTE_RRC_OTA_Packet":
            decoded_msg = msg.data.decode()
            config_xml = str(decoded_msg['Msg'])
            sr_index = re.search(r'sr-ConfigIndex: (\d+)',config_xml)
            if sr_index:
                # print(sr_index.group())
                # self.sr_time = (10 + int(sr_index.group(1)) - 5) % 10
                self.config_msg.write(str(sr_index.group())+"\n")
            onDurationTimer = re.search(r'onDurationTimer: psf(\d+)', config_xml)
            if onDurationTimer:
                self.config_msg.write(str(onDurationTimer.group()) + "\n")
            drx_InactivityTimer = re.search(r'drx-InactivityTimer: psf(\d+)', config_xml)
            if drx_InactivityTimer:
                self.config_msg.write(str(drx_InactivityTimer.group()) + "\n")
            drx_RetransmissionTimer = re.search(r'drx-RetransmissionTimer: psf(\d+)', config_xml)
            if drx_RetransmissionTimer:
                self.config_msg.write(str(drx_RetransmissionTimer.group()) + "\n")
            longDRX_CycleStartOffset = re.search(r'longDRX-CycleStartOffset: sf(\d+)', config_xml)
            if longDRX_CycleStartOffset:
                self.config_msg.write(str(longDRX_CycleStartOffset.group()) + "\n")
            shortDRX_Cycle = re.search(r'shortDRX-Cycle: sf(\d+)', config_xml)
            if shortDRX_Cycle:
                self.config_msg.write(str(shortDRX_Cycle.group()) + "\n")
            drxShortCycleTimer = re.search(r'drxShortCycleTimer: (\d+)', config_xml)
            if drxShortCycleTimer:
                self.config_msg.write(str(drxShortCycleTimer.group()) + "\n")

        elif msg.type_id == "LTE_RLC_UL_AM_All_PDU":
            # print("`LTE_RLC_UL_AM_All_PDU:", msg.data.decode())
            decoded_msg = msg.data.decode()
            for packet in decoded_msg['Subpackets']:
                # print("RLC Time:", msg.data.decode()['timestamp'])
                timestamp = int(datetime.timestamp(decoded_msg['timestamp']))
                for sample in packet['RLCUL PDUs']:
                    SFN = sample['sub_fn']
                    FN = sample['sys_fn']
                    data_type = sample['PDU TYPE']
                    # self.update_time(SFN, FN)
                    # if 'RLC DATA LI' in sample:
                    #     pdu_len = sample['pdu_bytes']
                    #     hdr_len = len(sample['RLC DATA LI'])+3
                    #     send_len = pdu_len - hdr_len
                    # else:
                    #     send_len = sample['pdu_bytes']
                    if data_type == "RLCUL DATA":
                        pdu_len = sample['pdu_bytes']
                        hdr_len = sample['logged_bytes']
                        send_len = pdu_len - hdr_len
                    else:
                        send_len = sample['pdu_bytes']

                    # calculate the round, add 20 to handle the disorder
                    if self.rlc_last_fn > FN + 20:
                        if self.synced == True:
                            self.synced = False
                        else:
                            self.rlc_round += 1
                    self.rlc_last_fn = FN

                    # self.rlc_msg += "RLC Time:" + str(decoded_msg['timestamp'])
                    # self.rlc_msg +=  "RLC: %s %s %s %s %s\n" % (timestamp, FN, SFN, data_type, send_len)
                    self.rlc_msg.write("RLC: %s %s %s %s %s\n" % (timestamp, FN, SFN, data_type, send_len))


        elif msg.type_id == "LTE_MAC_UL_Buffer_Status_Internal":
            decoded_msg = msg.data.decode()
            for packet in decoded_msg['Subpackets']:
                timestamp = int(datetime.timestamp(decoded_msg['timestamp']))
                # print(timestamp)
                for sample in packet['Samples']:
                    # print sample
                    SFN = sample['Sub FN']
                    FN = sample['Sys FN']
                    self.update_time(SFN, FN)
                    # print("Mac Time:", timestamp, self.fn, self.sfn )

                    # calculate the round
                    if self.fn < self.last_fn - 100 and self.fn != -1:
                        self.mac_round += 1
                    self.last_fn = self.fn

                    if (sample['LCIDs'] == []):
                        # print "error here!!"
                        continue
                    data = sample['LCIDs'][-1]
                    total_b = data['Total Bytes']
                    new_c = data['New Compressed Bytes']
                    # print("Mac Time:", timestamp, self.fn, self.sfn,total_b)

                    # self.mac_msg += "MAC Time:" + str(decoded_msg['timestamp'])
                    # self.mac_msg += "MAC: %s %s %s %s %s\n" % (timestamp, self.fn, self.sfn, total_b, new_c)
                    # self.mac_msg.write("MAC: %s %s %s %s %s %s\n" % (decoded_msg['timestamp'], timestamp, self.fn, self.sfn, total_b, new_c))
                    self.mac_msg.write("MAC: %s %s %s %s %s\n" % ( timestamp, self.fn, self.sfn, total_b, new_c))

                    if total_b > 0:
                        self.all_msg.write("%s %s %s Data %s %s\n" % (timestamp, self.fn, self.sfn, total_b, new_c))
                        # print("MAC:",  self.round, self.fn, self.sfn, total_b, new_c)
                        if total_b - self.last_buffer == self.pkt_size:
                            self.in_t = self.sfn + self.fn * 10

                    if total_b == 0 and self.in_t > 0:
                        # print("MAC:", self.fn, self.sfn, total_b, new_c)
                        t_diff = self.__f_time_diff(self.in_t, self.last_t) + 1
                        # print("From ", self.in_t, " to ", self.last_t + 1 ,"latency: ", t_diff)
                        self.latency_list.append(t_diff)
                        self.in_t = -1

                    self.last_buffer = total_b
                    self.last_t = self.sfn + self.fn * 10

    def update_time(self, SFN, FN):
        # print(SFN, FN)
        if self.sfn >= 0:      
            self.sfn += 1
            if self.sfn == 10:
                self.sfn = 0
                self.fn += 1
            if self.fn == 1024:
                self.fn = 0
        if SFN < 10:
            self.sfn = SFN
            self.fn = FN