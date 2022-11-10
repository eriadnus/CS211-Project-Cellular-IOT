#!/usr/bin/python

from mobile_insight.monitor import OfflineReplayer
from buffer_analyzer import BufferAnalyzer

import os
from enum import Enum

class FSM_States(Enum):
    Invalid = 0
    NoData = 1
    DataPending = 2
    SRTriggered = 3

class FSM_Actions(Enum):
    Data = 1
    SR = 2
    GrantwithPadding = 3
    GrantNoPadding = 4

class FSM_Checking:
    def __init__(self):
        self.state = FSM_States.Invalid # Init state

    def getState(self):
        return self.state

    def setState(self, state):
        self.state = state

    def stateTransition(self, action):
        if self.state == FSM_States.Invalid:
            if action == FSM_Actions.Data:
                return FSM_States.DataPending
            elif action == FSM_Actions.SR:
                return FSM_States.SRTriggered
            elif action == FSM_Actions.GrantwithPadding:
                return FSM_States.NoData
            elif action == FSM_Actions.GrantNoPadding:
                return FSM_States.SRTriggered
        elif self.state == FSM_States.NoData and action == FSM_Actions.Data:
            return FSM_States.DataPending
        elif self.state == FSM_States.DataPending and action == FSM_Actions.Data:
            return FSM_States.DataPending
        elif self.state == FSM_States.DataPending and action == FSM_Actions.SR:
            return FSM_States.SRTriggered
        elif self.state == FSM_States.SRTriggered and action == FSM_Actions.GrantwithPadding:
            return FSM_States.NoData
        elif self.state == FSM_States.SRTriggered and ( action == FSM_Actions.GrantNoPadding or action == FSM_Actions.Data):
            return FSM_States.SRTriggered
        else:
            print("invalid Action! Current state:", self.state, "; action:", action)
            return FSM_States.Invalid

paths = ['./logs/',]
filename_list = ['monitor-example-1665179984-cat-m-hologram']


def buffer_analysis():
    for path in paths:
        for filename in filename_list:
            src = OfflineReplayer()
            src.set_input_path(path + filename + '.qmdl')

            analyzer = BufferAnalyzer(path, filename)
            analyzer.set_source(src)

            src.run()
            print(path + filename + " Finished!")

            fsm = FSM_Checking()
            results_name = path + filename
            os.system(" sort " + results_name + "_all.txt -o " + results_name + "_sort_all.txt")

            for line in open(results_name + "_sort_all.txt", "r"):
                line = line.strip()
                line = line.split(" ")
                if line[3] == "Data":
                    curr_state = fsm.stateTransition(FSM_Actions.Data)
                elif line[3] == "SR":
                    curr_state = fsm.stateTransition(FSM_Actions.SR)
                elif line[3] == "Grant":
                    if int(line[5]) != 0:  # The grant is used up and not enough
                        curr_state = fsm.stateTransition(FSM_Actions.GrantNoPadding)
                    else:  # The grant is not used up and have padding
                        curr_state = fsm.stateTransition(FSM_Actions.GrantwithPadding)
                print(curr_state)
                fsm.setState(curr_state)


l = buffer_analysis()
