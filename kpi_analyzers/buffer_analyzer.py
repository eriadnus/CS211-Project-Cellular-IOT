#!/usr/bin/python
# Filename: buffer_analyzer.py
"""
Analyzer for RRCReconfiguration and RRCReconfigurationComplete.

Author: Jinghao Zhao & Ricky Guo
"""

__all__ = ["BufferAnalyzer"]

import re
from mobile_insight.analyzer.analyzer import *
from mobile_insight.analyzer import *
from enum import Enum

MINIMUM_HANDOVER_LATENCY = 0
MAXIMUM_HANDOVER_LATENCY = float('inf')
class RRCState(Enum):
    NOTHING = 0
    RRC_CONNECTION_REQUEST = 1
    RRC_CONNECTION_SETUP = 2
    RRC_CONNECTION_SETUP_COMPLETE = 3
    SECURITY_MODE_COMMAND = 4
    SECURITY_MODE_COMPLETE = 5
    MEASUREMENT_REPORT = 6
    RRC_NON_HANDOVER_RECONFIGURATION = 7
    RRC_HANDOVER_RECONFIGURATION = 8
    RRC_RECONFIGURATION_COMPLETE = 9

class NASState(Enum):
    NOTHING = 0
    ATTACH_REQUEST = 15
    AUTHENTICATION_REQUEST = 1
    AUTHENTICATION_RESPONSE = 2
    SECURITY_MODE_COMMAND = 3
    SECURITY_MODE_COMPLETE = 4
    ESM_INFORMATION_REQUEST = 5
    ESM_INFORMATION_RESPONSE = 6
    ATTACH_ACCEPT = 7
    SERVICE_REQUEST = 8
    PDN_CONNECTIVITY_REQUEST = 9
    ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST = 10
    ACTIVATE_DEFAULT_EPS_BEARER_ACCEPT_REQUEST = 11
    ATTACH_COMPLETE = 12
    TRACKING_AREA_UPDATE_REQUEST = 13
    TRACKING_AREA_UPDATE_ACCEPT = 14

class BufferAnalyzer(Analyzer):
    """
    A KPI analyzer to derive signals for handover latency.
    """

    """
    RRC filtering.
    """
    @staticmethod
    def has_rrc_connection_request_record(message):
        if message.type_id == 'LTE_RRC_OTA_Packet':
            decoded_message = str(message.data.decode())
            return 'showname="rrcConnectionRequest"' in decoded_message
        return False

    @staticmethod
    def has_rrc_connection_setup_record(message):
        if message.type_id == 'LTE_RRC_OTA_Packet':
            decoded_message = str(message.data.decode())
            return 'showname="rrcConnectionSetup"' in decoded_message
        return False

    @staticmethod
    def has_rrc_connection_setup_complete_record(message):
        if message.type_id == 'LTE_RRC_OTA_Packet':
            decoded_message = str(message.data.decode())
            return 'showname="rrcConnectionSetupComplete"' in decoded_message
        return False

    @staticmethod
    def has_rrc_connection_security_mode_command_record(message):
        if message.type_id == 'LTE_RRC_OTA_Packet':
            decoded_message = str(message.data.decode())
            return 'showname="securityModeCommand"' in decoded_message
        return False
    @staticmethod
    def has_rrc_connection_security_mode_complete_record(message):
        if message.type_id == 'LTE_RRC_OTA_Packet':
            decoded_message = str(message.data.decode())
            return 'showname="securityModeComplete"' in decoded_message
        return False
    @staticmethod
    def has_rrc_measurement_report_record(message):
        if message.type_id == 'LTE_RRC_OTA_Packet':
            decoded_message = str(message.data.decode())
            return 'showname="measurementReport"' in decoded_message
        return False
    @staticmethod
    def has_handover_rrc_connection_reconfiguration_record(message):
        if message.type_id == 'LTE_RRC_OTA_Packet':
            decoded_message = str(message.data.decode())
            return 'targetPhysCellId' in decoded_message \
                and 'showname="rrcConnectionReconfiguration"' in decoded_message
        return False

    @staticmethod
    def has_non_handover_rrc_connection_reconfiguration_record(message):
        if message.type_id == 'LTE_RRC_OTA_Packet':
            decoded_message = str(message.data.decode())
            return 'targetPhysCellId' not in decoded_message \
                   and 'showname="rrcConnectionReconfiguration"' in decoded_message
        return False

    @staticmethod
    def has_rrc_connection_reconfiguration_complete_record(message):
        if message.type_id == 'LTE_RRC_OTA_Packet':
            decoded_message = str(message.data.decode())
            return 'showname="rrcConnectionReconfigurationComplete"' in decoded_message
        return False

    """
    NAS filtering.
    """
    @staticmethod
    def has_nas_attach_request_record(message):
        if message.type_id == 'LTE_NAS_EMM_OTA_Outgoing_Packet':
            decoded_message = str(message.data.decode())
            return 'showname="NAS EPS Mobility Management Message Type: Attach request (0x41)"' in decoded_message
        return False

    @staticmethod
    def has_nas_authentication_request_record(message):
        if message.type_id == 'LTE_NAS_EMM_OTA_Incoming_Packet':
            decoded_message = str(message.data.decode())
            return 'showname="NAS EPS Mobility Management Message Type: Authentication request (0x52)"' in decoded_message
        return False

    @staticmethod
    def has_nas_authentication_response_record(message):
        if message.type_id == 'LTE_NAS_EMM_OTA_Outgoing_Packet':
            decoded_message = str(message.data.decode())
            return 'showname="NAS EPS Mobility Management Message Type: Authentication response (0x53)"' in decoded_message
        return False

    @staticmethod
    def has_nas_security_mode_command_record(message):
        if message.type_id == 'LTE_NAS_EMM_OTA_Incoming_Packet':
            decoded_message = str(message.data.decode())
            return 'showname="NAS EPS Mobility Management Message Type: Security mode command (0x5d)"' in decoded_message
        return False

    @staticmethod
    def has_nas_security_mode_complete_record(message):
        if message.type_id == 'LTE_NAS_EMM_OTA_Outgoing_Packet':
            decoded_message = str(message.data.decode())
            return 'showname="NAS EPS Mobility Management Message Type: Security mode complete (0x5e)"' in decoded_message
        return False

    @staticmethod
    def has_nas_esm_information_request_record(message):
        if message.type_id == 'LTE_NAS_ESM_OTA_Incoming_Packet':
            decoded_message = str(message.data.decode())
            return 'showname="NAS EPS session management messages: ESM information request (0xd9)"' in decoded_message
        return False

    @staticmethod
    def has_nas_esm_information_response_record(message):
        if message.type_id == 'LTE_NAS_ESM_OTA_Outgoing_Packet':
            decoded_message = str(message.data.decode())
            return 'showname="NAS EPS session management messages: ESM information response (0xda)"' in decoded_message
        return False

    @staticmethod
    def has_nas_attach_accept_record(message):
        if message.type_id == 'LTE_NAS_EMM_OTA_Incoming_Packet':
            decoded_message = str(message.data.decode())
            return 'showname="NAS EPS Mobility Management Message Type: Attach accept (0x42)"' in decoded_message
        return False

    @staticmethod
    def has_nas_service_request_record(message):
        if message.type_id == 'LTE_NAS_EMM_OTA_Outgoing_Packet':
            decoded_message = str(message.data.decode())
            return 'showname="1100 .... = Security header type: Security header for the SERVICE REQUEST message (12)"' in decoded_message
        return False

    @staticmethod
    def has_nas_pdn_connectivity_request_record(message):
        if message.type_id == 'LTE_NAS_ESM_OTA_Outgoing_Packet':
            decoded_message = str(message.data.decode())
            return 'showname="NAS EPS session management messages: PDN connectivity request (0xd0)"' in decoded_message
        return False

    @staticmethod
    def has_nas_activate_default_eps_bearer_context_request_record(message):
        if message.type_id == 'LTE_NAS_ESM_OTA_Incoming_Packet':
            decoded_message = str(message.data.decode())
            return 'showname="NAS EPS session management messages: Activate default EPS bearer context request (0xc1)"' in decoded_message
        return False

    @staticmethod
    def has_nas_activate_default_eps_bearer_context_accept_record(message):
        if message.type_id == 'LTE_NAS_ESM_OTA_Outgoing_Packet':
            decoded_message = str(message.data.decode())
            return 'showname="NAS EPS session management messages: Activate default EPS bearer context accept (0xc2)"' in decoded_message
        return False

    @staticmethod
    def has_nas_attach_complete_record(message):
        if message.type_id  == 'LTE_NAS_EMM_OTA_Outgoing_Packet':
            decoded_message = str(message.data.decode())
            return 'showname="NAS EPS Mobility Management Message Type: Attach complete (0x43)"' in decoded_message
        return False

    @staticmethod
    def has_nas_tracking_area_update_request(message):
        if message.type_id == 'LTE_NAS_EMM_OTA_Outgoing_Packet':
            decoded_message = str(message.data.decode())
            return 'showname="NAS EPS Mobility Management Message Type: Tracking area update request (0x48)"' in decoded_message
        return False

    @staticmethod
    def has_nas_tracking_area_update_accept(message):
        if message.type_id == 'LTE_NAS_EMM_OTA_Incoming_Packet':
            decoded_message = str(message.data.decode())
            return 'showname="NAS EPS Mobility Management Message Type: Tracking area update accept (0x49)"' in decoded_message
        return False

    @staticmethod
    def get_timedelta_millis(time_delta):
        return time_delta.microseconds / 1000

    def __init__(self):
        Analyzer.__init__(self)

        # Options
        self.silence_rrc_parsing_logs = True
        self.silence_nas_parsing_logs = True

        self.add_source_callback(self.__rrc_message_callback)
        self.rrc_split_latency_metrics = {
            'connection_request_to_connection_setup': [],
            'connection_setup_to_connection_setup_complete': [],
            'connection_setup_complete_to_security_mode_command': [],
            'security_mode_command_to_security_mode_complete': [],
            'non_handover_security_mode_complete_to_connection_reconfiguration': [],
            'handover_measurement_report_to_connection_reconfiguration': [],
            'non_handover_connection_reconfiguration_to_connection_reconfiguration_complete': [],
            'handover_connection_reconfiguration_to_connection_reconfiguration_complete': [],
        }
        self.rrc_message_timestamps = {}
        self.rrc_previous_state = RRCState.NOTHING

        self.add_source_callback(self.__nas_message_callback)
        self.nas_split_latency_metrics = {
            'attach_request_to_authentication_request': [],
            'authentication_request_to_authentication_response': [],
            'authentication_response_to_security_mode_command': [],
            'security_mode_command_to_security_mode_complete': [],
            'security_mode_complete_to_esm_information_request': [],
            'esm_information_request_to_esm_information_response': [],
            'esm_information_response_to_attach_accept': [],
            'active_activate_default_eps_bearer_context_request_to_activate_default_eps_bearer_context_accept': [],
            'idle_activate_default_eps_bearer_context_request_to_activate_default_eps_bearer_context_accept': [],
            'activate_default_eps_bearer_context_request_to_attach_complete': [],
            'attach_complete_to_pdn_connectivity_request': [],
            'active_pdn_connectivity_request_to_activate_default_eps_bearer_context_request': [],
            'idle_pdn_connectivity_request_to_activate_default_eps_bearer_context_request': [],
            'service_request_to_pdn_connectivity_request': [],
            'service_request_to_tracking_area_update_request': [],
            'tracking_area_update_request_to_tracking_area_update_accept': [],
        }
        self.nas_message_timestamps = {}
        self.nas_previous_state = NASState.NOTHING
        self.nas_previous_previous_state = NASState.NOTHING
        self.nas_previous_previous_previous_state = NASState.NOTHING

    def set_source(self, source):
        """
        Set the trace source. Enable the cellular signaling messages

        :param source: the trace source (collector).
        """
        Analyzer.set_source(self, source)

        # Enable RRC Logging
        source.enable_log('LTE_RRC_OTA_Packet')

        # Enable NAS Logging
        source.enable_log('LTE_NAS_ESM_OTA_Outgoing_Packet')
        source.enable_log('LTE_NAS_EMM_OTA_Outgoing_Packet')
        source.enable_log('LTE_NAS_ESM_OTA_Incoming_Packet')
        source.enable_log('LTE_NAS_EMM_OTA_Incoming_Packet')

    def rrc_logging_silencer(self, rrc_logging_message):
        if not self.silence_rrc_parsing_logs:
            print(rrc_logging_message)
    def __rrc_message_callback(self, message):
        decoded_message = message.data.decode()
        if BufferAnalyzer.has_rrc_connection_request_record(message):
            self.rrc_logging_silencer('[1] Parsing connection request record.')
            self.rrc_message_timestamps['connection_request'] = decoded_message['timestamp']
            self.rrc_previous_state = RRCState.RRC_CONNECTION_REQUEST
        if BufferAnalyzer.has_rrc_connection_setup_record(message):
            self.rrc_logging_silencer('[2] Parsing connection setup record.')
            self.rrc_message_timestamps['connection_setup'] = decoded_message['timestamp']
            if self.rrc_previous_state != RRCState.RRC_CONNECTION_REQUEST:
                print('Encountered invalid state transition from {} to {}'.format(
                    self.rrc_previous_state, RRCState.RRC_CONNECTION_SETUP
                ))
            else:
                self.rrc_split_latency_metrics['connection_request_to_connection_setup'].append(
                    BufferAnalyzer.get_timedelta_millis(self.rrc_message_timestamps['connection_setup'] - self.rrc_message_timestamps['connection_request'])
                )
            self.rrc_previous_state = RRCState.RRC_CONNECTION_SETUP
        if BufferAnalyzer.has_rrc_connection_setup_complete_record(message):
            self.rrc_logging_silencer('[3] Parsing connection setup complete record.')
            self.rrc_message_timestamps['connection_setup_complete'] = decoded_message['timestamp']
            if self.rrc_previous_state != RRCState.RRC_CONNECTION_SETUP:
                print('Encountered invalid state transition from {} to {}'.format(
                    self.rrc_previous_state, RRCState.RRC_CONNECTION_SETUP_COMPLETE
                ))
            else:
                self.rrc_split_latency_metrics['connection_setup_to_connection_setup_complete'].append(
                    BufferAnalyzer.get_timedelta_millis(self.rrc_message_timestamps['connection_setup_complete'] - self.rrc_message_timestamps['connection_setup'])
                )
            self.rrc_previous_state = RRCState.RRC_CONNECTION_SETUP_COMPLETE
        if BufferAnalyzer.has_rrc_connection_security_mode_command_record(message):
            self.rrc_logging_silencer('[4] Parsing connection security mode command record.')
            self.rrc_message_timestamps['security_mode_command'] = decoded_message['timestamp']
            if self.rrc_previous_state != RRCState.RRC_CONNECTION_SETUP_COMPLETE:
                print('Encountered invalid state transition from {} to {}'.format(
                    self.rrc_previous_state, RRCState.SECURITY_MODE_COMMAND
                ))
            else:
                self.rrc_split_latency_metrics['connection_setup_complete_to_security_mode_command'].append(
                    BufferAnalyzer.get_timedelta_millis(self.rrc_message_timestamps['security_mode_command'] - self.rrc_message_timestamps['connection_setup_complete'])
                )
            self.rrc_previous_state = RRCState.SECURITY_MODE_COMMAND
        if BufferAnalyzer.has_rrc_connection_security_mode_complete_record(message):
            self.rrc_logging_silencer('[5.a] Parsing connection security mode complete record.')
            self.rrc_message_timestamps['security_mode_complete'] = decoded_message['timestamp']
            if self.rrc_previous_state != RRCState.SECURITY_MODE_COMMAND:
                print('Invalid state transition from {} to {}'.format(
                    self.rrc_previous_state, RRCState.SECURITY_MODE_COMPLETE
                ))
            else:
                self.rrc_split_latency_metrics['security_mode_command_to_security_mode_complete'].append(
                    BufferAnalyzer.get_timedelta_millis(self.rrc_message_timestamps['security_mode_complete'] - self.rrc_message_timestamps['security_mode_command'])
                )
            self.rrc_previous_state = RRCState.SECURITY_MODE_COMPLETE
        if BufferAnalyzer.has_rrc_measurement_report_record(message):
            self.rrc_logging_silencer('[5.b] Parsing measurement report record.')
            self.rrc_message_timestamps['measurement_report'] = decoded_message['timestamp']
            self.rrc_previous_state = RRCState.MEASUREMENT_REPORT
        if BufferAnalyzer.has_non_handover_rrc_connection_reconfiguration_record(message):
            self.rrc_logging_silencer('[6.a] Parsing non-handover connection reconfiguration record.')
            self.rrc_message_timestamps['non_handover_reconfiguration'] = decoded_message['timestamp']
            if self.rrc_previous_state != RRCState.SECURITY_MODE_COMPLETE:
                print('Invalid state transition from {} to {}'.format(
                    self.rrc_previous_state, RRCState.RRC_NON_HANDOVER_RECONFIGURATION
                ))
            else:
                self.rrc_split_latency_metrics['non_handover_security_mode_complete_to_connection_reconfiguration'].append(
                    BufferAnalyzer.get_timedelta_millis(
                        self.rrc_message_timestamps['non_handover_reconfiguration'] - self.rrc_message_timestamps['security_mode_complete'])
                )
            self.rrc_previous_state = RRCState.RRC_NON_HANDOVER_RECONFIGURATION
        if BufferAnalyzer.has_handover_rrc_connection_reconfiguration_record(message):
            self.rrc_logging_silencer('[6.b] Parsing handover connection reconfiguration record.')
            self.rrc_message_timestamps['handover_reconfiguration'] = decoded_message['timestamp']
            if self.rrc_previous_state != RRCState.MEASUREMENT_REPORT:
                print('Invalid state transition from {} to {}'.format(
                    self.rrc_previous_state, RRCState.RRC_HANDOVER_RECONFIGURATION
                ))
            else:
                self.rrc_split_latency_metrics['handover_measurement_report_to_connection_reconfiguration'].append(
                    BufferAnalyzer.get_timedelta_millis(self.rrc_message_timestamps['handover_reconfiguration'] - self.rrc_message_timestamps['measurement_report'])
                )
            self.rrc_previous_state = RRCState.RRC_HANDOVER_RECONFIGURATION
        if BufferAnalyzer.has_rrc_connection_reconfiguration_complete_record(message):
            self.rrc_logging_silencer('[7] Parsing connection reconfiguration complete record.')
            self.rrc_message_timestamps['reconfiguration_complete'] = decoded_message['timestamp']
            if self.rrc_previous_state == RRCState.RRC_NON_HANDOVER_RECONFIGURATION:
                self.rrc_split_latency_metrics['non_handover_connection_reconfiguration_to_connection_reconfiguration_complete'].append(
                    BufferAnalyzer.get_timedelta_millis(self.rrc_message_timestamps['non_handover_reconfiguration']
                    - self.rrc_message_timestamps['reconfiguration_complete'])
                )
            elif self.rrc_previous_state == RRCState.RRC_HANDOVER_RECONFIGURATION:
                self.rrc_split_latency_metrics['handover_connection_reconfiguration_to_connection_reconfiguration_complete'].append(
                    BufferAnalyzer.get_timedelta_millis(self.rrc_message_timestamps['handover_reconfiguration']
                    - self.rrc_message_timestamps['reconfiguration_complete'])
                )
            else:
                print('Invalid state transition from {} to {}'.format(
                    self.rrc_previous_state, RRCState.RRC_CONNECTION_SETUP_COMPLETE
                ))
            self.rrc_previous_state = RRCState.RRC_CONNECTION_SETUP_COMPLETE

    def nas_logging_silencer(self, nas_logging_message):
        if not self.silence_nas_parsing_logs:
            print(nas_logging_message)
    def __nas_message_callback(self, message):
        decoded_message = message.data.decode()
        if BufferAnalyzer.has_nas_attach_request_record(message):
            self.nas_logging_silencer('[1a] Parsing attach request record.')
            self.nas_message_timestamps['attach_request'] = decoded_message['timestamp']
            self.nas_previous_state, self.nas_previous_previous_state, self.nas_previous_previous_previous_state = NASState.ATTACH_REQUEST, self.nas_previous_state, self.nas_previous_previous_state
        if BufferAnalyzer.has_nas_authentication_request_record(message):
            self.nas_logging_silencer('[2a] Parsing authentication request record.')
            self.nas_message_timestamps['authentication_request'] = decoded_message['timestamp']
            if self.nas_previous_state != NASState.ATTACH_REQUEST:
                print('Invalid state transition from {} to {}'.format(
                    self.nas_previous_state, NASState.AUTHENTICATION_REQUEST
                ))
            else:
                self.nas_split_latency_metrics['attach_request_to_authentication_request'].append(
                    BufferAnalyzer.get_timedelta_millis(self.nas_message_timestamps['authentication_request']
                    - self.nas_message_timestamps['attach_request'])
                )
            self.nas_previous_state, self.nas_previous_previous_state, self.nas_previous_previous_previous_state = NASState.AUTHENTICATION_REQUEST, self.nas_previous_state, self.nas_previous_previous_state
        if BufferAnalyzer.has_nas_authentication_response_record(message):
            self.nas_logging_silencer('[3a] Parsing authentication response record.')
            self.nas_message_timestamps['authentication_response'] = decoded_message['timestamp']
            if self.nas_previous_state != NASState.AUTHENTICATION_REQUEST:
                print('Invalid state transition from {} to {}'.format(
                    self.nas_previous_state, NASState.AUTHENTICATION_RESPONSE
                ))
            else:
                self.nas_split_latency_metrics['authentication_request_to_authentication_response'].append(
                    BufferAnalyzer.get_timedelta_millis(self.nas_message_timestamps['authentication_response']
                    - self.nas_message_timestamps['authentication_request'])
                )
            self.nas_previous_state, self.nas_previous_previous_state, self.nas_previous_previous_previous_state = NASState.AUTHENTICATION_RESPONSE, self.nas_previous_state, self.nas_previous_previous_state
        if BufferAnalyzer.has_nas_security_mode_command_record(message):
            self.nas_logging_silencer('[4a] Parsing security mode command record.')
            self.nas_message_timestamps['security_mode_command'] = decoded_message['timestamp']
            if self.nas_previous_state != NASState.AUTHENTICATION_RESPONSE:
                print('Invalid state transition from {} to {}'.format(
                    self.nas_previous_state, NASState.SECURITY_MODE_COMMAND
                ))
            else:
                self.nas_split_latency_metrics['authentication_response_to_security_mode_command'].append(
                    BufferAnalyzer.get_timedelta_millis(self.nas_message_timestamps['authentication_response']
                    - self.nas_message_timestamps['security_mode_command'])
                )
            self.nas_previous_state, self.nas_previous_previous_state, self.nas_previous_previous_previous_state = NASState.SECURITY_MODE_COMMAND, self.nas_previous_state, self.nas_previous_previous_state
        if BufferAnalyzer.has_nas_security_mode_complete_record(message):
            self.nas_logging_silencer('[5a] Parsing security mode complete record.')
            self.nas_message_timestamps['security_mode_complete'] = decoded_message['timestamp']
            if self.nas_previous_state != NASState.SECURITY_MODE_COMMAND:
                print('Invalid state transition from {} to {}'.format(
                    self.nas_previous_state, NASState.SECURITY_MODE_COMPLETE
                ))
            else:
                self.nas_split_latency_metrics['security_mode_command_to_security_mode_complete'].append(
                    BufferAnalyzer.get_timedelta_millis(self.nas_message_timestamps['security_mode_command']
                    - self.nas_message_timestamps['security_mode_complete'])
                )
            self.nas_previous_state, self.nas_previous_previous_state, self.nas_previous_previous_previous_state = NASState.SECURITY_MODE_COMPLETE, self.nas_previous_state, self.nas_previous_previous_state
        if BufferAnalyzer.has_nas_esm_information_request_record(message):
            self.nas_logging_silencer('[6a] Parsing esm information request record.')
            self.nas_message_timestamps['esm_information_request'] = decoded_message['timestamp']
            if self.nas_previous_state != NASState.SECURITY_MODE_COMPLETE:
                print('Invalid state transition from {} to {}'.format(
                    self.nas_previous_state, NASState.ESM_INFORMATION_REQUEST
                ))
            else:
                self.nas_split_latency_metrics['security_mode_complete_to_esm_information_request'].append(
                    BufferAnalyzer.get_timedelta_millis(self.nas_message_timestamps['security_mode_complete']
                    - self.nas_message_timestamps['esm_information_request'])
                )
            self.nas_previous_state, self.nas_previous_previous_state, self.nas_previous_previous_previous_state = NASState.ESM_INFORMATION_REQUEST, self.nas_previous_state, self.nas_previous_previous_state
        if BufferAnalyzer.has_nas_esm_information_response_record(message):
            self.nas_logging_silencer('[7a] Parsing esm information response record.')
            self.nas_message_timestamps['esm_information_response'] = decoded_message['timestamp']
            if self.nas_previous_state != NASState.ESM_INFORMATION_REQUEST:
                print('Invalid state transition from {} to {}'.format(
                    self.nas_previous_state, NASState.ESM_INFORMATION_RESPONSE
                ))
            else:
                self.nas_split_latency_metrics['esm_information_request_to_esm_information_response'].append(
                    BufferAnalyzer.get_timedelta_millis(self.nas_message_timestamps['esm_information_request']
                    - self.nas_message_timestamps['esm_information_response'])
                )
            self.nas_previous_state, self.nas_previous_previous_state, self.nas_previous_previous_previous_state = NASState.ESM_INFORMATION_RESPONSE.ESM_INFORMATION_RESPONSE, self.nas_previous_state, self.nas_previous_previous_state
        if BufferAnalyzer.has_nas_attach_accept_record(message):
            self.nas_logging_silencer('[8.1a] Parsing attach accept record.')
            self.nas_message_timestamps['attach_accept'] = decoded_message['timestamp']
            if self.nas_previous_state != NASState.ESM_INFORMATION_RESPONSE:
                print('Invalid state transition from {} to {}'.format(
                    self.nas_previous_state, NASState.ATTACH_ACCEPT
                ))
            else:
                self.nas_split_latency_metrics['esm_information_response_to_attach_accept'].append(
                    BufferAnalyzer.get_timedelta_millis(self.nas_message_timestamps['attach_accept']
                    - self.nas_message_timestamps['esm_information_response'])
                )
            self.nas_previous_state, self.nas_previous_previous_state, self.nas_previous_previous_previous_state = NASState.AUTHENTICATION_RESPONSE, self.nas_previous_state, self.nas_previous_previous_state
        if BufferAnalyzer.has_nas_activate_default_eps_bearer_context_request_record(message):
            self.nas_logging_silencer('[8.2a/11a/3b] Parsing nas activate default eps bearer context request record.')
            self.nas_message_timestamps['activate_default_eps_bearer_context_request'] = decoded_message['timestamp']
            if self.nas_previous_state == NASState.PDN_CONNECTIVITY_REQUEST and self.nas_previous_previous_state != NASState.SERVICE_REQUEST:
                self.nas_split_latency_metrics['active_pdn_connectivity_request_to_activate_default_eps_bearer_context_request'].append(
                    BufferAnalyzer.get_timedelta_millis(self.nas_message_timestamps['pdn_connectivity_request']
                    - self.nas_message_timestamps['activate_default_eps_bearer_context_request'])
                )
            elif self.nas_previous_state == NASState.PDN_CONNECTIVITY_REQUEST and self.nas_previous_previous_state == NASState.SERVICE_REQUEST:
                self.nas_split_latency_metrics['idle_pdn_connectivity_request_to_activate_default_eps_bearer_context_request'].append(
                    BufferAnalyzer.get_timedelta_millis(self.nas_message_timestamps['pdn_connectivity_request']
                    - self.nas_message_timestamps['activate_default_eps_bearer_context_request'])
                )
            else:
                print('Invalid state transition from {} to {}'.format(
                    self.nas_previous_state, NASState.ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST
                ))
            self.nas_previous_state, self.nas_previous_previous_state, self.nas_previous_previous_previous_state = NASState.ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST, self.nas_previous_state, self.nas_previous_previous_state
        if BufferAnalyzer.has_nas_attach_complete_record(message):
            self.nas_logging_silencer('[9a] Parsing attach complete record.')
            self.nas_message_timestamps['attach_complete'] = decoded_message['timestamp']
            if self.nas_previous_state != NASState.ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST:
                print('Invalid state transition from {} to {}'.format(
                    self.nas_previous_state, NASState.ATTACH_COMPLETE
                ))
            else:
                self.nas_split_latency_metrics['activate_default_eps_bearer_context_request_to_attach_complete'].append(
                    BufferAnalyzer.get_timedelta_millis(self.nas_message_timestamps['attach_complete']
                    - self.nas_message_timestamps['activate_default_eps_bearer_context_request'])
                )
            self.nas_previous_state, self.nas_previous_previous_state, self.nas_previous_previous_previous_state = NASState.ATTACH_COMPLETE, self.nas_previous_state, self.nas_previous_previous_state
        if BufferAnalyzer.has_nas_service_request_record(message):
            self.nas_logging_silencer('[1b/1c] Parsing nas service request record.')
            self.nas_message_timestamps['service_request'] = decoded_message['timestamp']
            self.nas_previous_state, self.nas_previous_previous_state, self.nas_previous_previous_previous_state = NASState.SERVICE_REQUEST, self.nas_previous_state, self.nas_previous_previous_state
        if BufferAnalyzer.has_nas_pdn_connectivity_request_record(message):
            self.nas_logging_silencer('[10a/2b] Parsing nas pdn connectivity request record.')
            self.nas_message_timestamps['pdn_connectivity_request'] = decoded_message['timestamp']
            if self.nas_previous_state == NASState.ATTACH_COMPLETE:
                self.nas_split_latency_metrics['attach_complete_to_pdn_connectivity_request'].append(
                    BufferAnalyzer.get_timedelta_millis(self.nas_message_timestamps['pdn_connectivity_request']
                    - self.nas_message_timestamps['attach_complete'])
                )
            elif self.nas_previous_state == NASState.SERVICE_REQUEST:
                self.nas_split_latency_metrics['service_request_to_pdn_connectivity_request'].append(
                    BufferAnalyzer.get_timedelta_millis(self.nas_message_timestamps['pdn_connectivity_request']
                    - self.nas_message_timestamps['service_request'])
                )
            else:
                print('Invalid state transition from {} to {}'.format(
                    self.nas_previous_state, NASState.PDN_CONNECTIVITY_REQUEST
                ))
            self.nas_previous_state, self.nas_previous_previous_state, self.nas_previous_previous_previous_state = NASState.PDN_CONNECTIVITY_REQUEST, self.nas_previous_state, self.nas_previous_previous_state
        if BufferAnalyzer.has_nas_tracking_area_update_request(message):
            self.nas_logging_silencer('[2c] Parsing nas tracking area update request.')
            self.nas_message_timestamps['tracking_area_update_request'] = decoded_message['timestamp']
            if self.nas_previous_state != NASState.SERVICE_REQUEST:
                print('Invalid state transition from {} to {}'.format(
                    self.nas_previous_state, NASState.TRACKING_AREA_UPDATE_REQUEST
                ))
            else:
                self.nas_split_latency_metrics['service_request_to_tracking_area_update_request'].append(
                    BufferAnalyzer.get_timedelta_millis(self.nas_message_timestamps['tracking_area_update_request']
                    - self.nas_message_timestamps['service_request'])
                )
            self.nas_previous_state, self.nas_previous_previous_state, self.nas_previous_previous_previous_state = NASState.TRACKING_AREA_UPDATE_REQUEST, self.nas_previous_state, self.nas_previous_previous_state
        if BufferAnalyzer.has_nas_tracking_area_update_accept(message):
            self.nas_logging_silencer('[3c] Parsing nas tracking area update accept.')
            self.nas_message_timestamps['tracking_area_update_accept'] = decoded_message['timestamp']
            if self.nas_previous_state != NASState.TRACKING_AREA_UPDATE_REQUEST:
                print('Invalid state transition from {} to {}'.format(
                    self.nas_previous_state, NASState.TRACKING_AREA_UPDATE_ACCEPT
                ))
            else:
                self.nas_split_latency_metrics['tracking_area_update_request_to_tracking_area_update_accept'].append(
                    BufferAnalyzer.get_timedelta_millis(self.nas_message_timestamps['tracking_area_update_accept']
                    - self.nas_message_timestamps['tracking_area_update_request'])
                )
            self.nas_previous_state, self.nas_previous_previous_state, self.nas_previous_previous_previous_state = NASState.TRACKING_AREA_UPDATE_ACCEPT, self.nas_previous_state, self.nas_previous_previous_state
        if BufferAnalyzer.has_nas_activate_default_eps_bearer_context_accept_record(message):
            self.nas_logging_silencer('[12a/4b] Parsing nas activate default eps bearer context accept record.')
            self.nas_message_timestamps['activate_default_eps_bearer_context_accept'] = decoded_message['timestamp']
            if self.nas_previous_state == NASState.ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST and self.nas_previous_previous_state == NASState.PDN_CONNECTIVITY_REQUEST and self.nas_previous_previous_previous_state == NASState.ATTACH_COMPLETE:
                self.nas_split_latency_metrics['active_activate_default_eps_bearer_context_request_to_activate_default_eps_bearer_context_accept'].append(
                    BufferAnalyzer.get_timedelta_millis(self.nas_message_timestamps['activate_default_eps_bearer_context_request']
                    - self.nas_message_timestamps['activate_default_eps_bearer_context_accept'])
                )
            elif self.nas_previous_state == NASState.ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST and self.nas_previous_previous_state == NASState.PDN_CONNECTIVITY_REQUEST and self.nas_previous_previous_previous_state == NASState.SERVICE_REQUEST:
                self.nas_split_latency_metrics['idle_activate_default_eps_bearer_context_request_to_activate_default_eps_bearer_context_accept'].append(
                    BufferAnalyzer.get_timedelta_millis(self.nas_message_timestamps['activate_default_eps_bearer_context_request']
                    - self.nas_message_timestamps['activate_default_eps_bearer_context_accept'])
                )
            else:
                print('Invalid state transition from {} to {}'.format(
                    self.nas_previous_state, NASState.ACTIVATE_DEFAULT_EPS_BEARER_ACCEPT_REQUEST
                ))
            self.nas_previous_state, self.nas_previous_previous_state, self.nas_previous_previous_previous_state = NASState.ACTIVATE_DEFAULT_EPS_BEARER_ACCEPT_REQUEST, self.nas_previous_state, self.nas_previous_previous_state