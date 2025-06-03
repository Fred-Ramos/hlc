##########################################################################################################################################################################################
import asyncio
import os

############################################################################### IEC Charger Class #######################################################################################
from evse.iec61851 import IEC61851_Handler
from evse.iec61851.basic_charging.build_basic_charging import ChargeMode

############################################################################### SLAC ####################################################################################################
from evse.hlc.slac_handler import Slac_Handler

from pyslac.enums import (
    COMMUNICATION_UNDEFINED,
    COMMUNICATION_HLC_READY,
    COMMUNICATION_LLC,
    COMMUNICATION_HLC)

###################################################### Logs ##########################################################################################################################
import logging
logger = logging.getLogger(__name__)
########################################################################## ISO15118 MODULE ################################################################################################
"""
This module contains the code to retrieve (hardware-related) data from the EVSE
(Electric Vehicle Supply Equipment).
"""

import base64
import time
from typing import Dict, List, Optional, Union

from iso15118.secc.controller.common import UnknownEnergyService
from iso15118.secc.controller.evse_data import (
    EVSEACCLLimits,
    EVSEACCPDLimits,
    EVSEDataContext,
    EVSEDCCLLimits,
    EVSEDCCPDLimits,
    EVSERatedLimits,
    EVSESessionLimits,
)
from iso15118.secc.controller.interface import (
    AuthorizationResponse,
    EVDataContext,
    EVSEControllerInterface,
    ServiceStatus,
)
from iso15118.shared.exceptions import EncryptionError, PrivateKeyReadError
from iso15118.shared.exi_codec import EXI
from iso15118.shared.messages.datatypes import (
    DCEVSEChargeParameter,
    DCEVSEStatus,
    DCEVSEStatusCode,
)
from iso15118.shared.messages.datatypes import EVSENotification as EVSENotificationV2
from iso15118.shared.messages.datatypes import (
    PVEVSEMaxCurrentLimit,
    PVEVSEMaxPowerLimit,
    PVEVSEMaxVoltageLimit,
    PVEVSEMinCurrentLimit,
    PVEVSEMinVoltageLimit,
    PVEVSEPeakCurrentRipple,
)
from iso15118.shared.messages.din_spec.datatypes import (
    PMaxScheduleEntry as PMaxScheduleEntryDINSPEC,
)
from iso15118.shared.messages.din_spec.datatypes import (
    PMaxScheduleEntryDetails as PMaxScheduleEntryDetailsDINSPEC,
)
from iso15118.shared.messages.din_spec.datatypes import (
    RelativeTimeInterval as RelativeTimeIntervalDINSPEC,
)
from iso15118.shared.messages.din_spec.datatypes import (
    ResponseCode as ResponseCodeDINSPEC,
)
from iso15118.shared.messages.din_spec.datatypes import (
    SAScheduleTupleEntry as SAScheduleTupleEntryDINSPEC,
)
from iso15118.shared.messages.enums import (
    AuthorizationStatus,
    AuthorizationTokenType,
    ControlMode,
    CpState,
    EnergyTransferModeEnum,
    IsolationLevel,
    Namespace,
    PriceAlgorithm,
    Protocol,
    ServiceV20,
    SessionStopAction,
    UnitSymbol,
)
from iso15118.shared.messages.iso15118_2.body import (
    Body,
    CertificateInstallationReq,
    CertificateInstallationRes,
)
from iso15118.shared.messages.iso15118_2.datatypes import (
    EMAID,
    ACEVSEChargeParameter,
    ACEVSEStatus,
    CertificateChain,
    DHPublicKey,
    EncryptedPrivateKey,
)
from iso15118.shared.messages.iso15118_2.datatypes import MeterInfo as MeterInfoV2
from iso15118.shared.messages.iso15118_2.datatypes import (
    PMaxSchedule,
    PMaxScheduleEntry,
    PVEVSEMaxCurrent,
    PVEVSENominalVoltage,
    PVPMax,
    RelativeTimeInterval,
)
from iso15118.shared.messages.iso15118_2.datatypes import ResponseCode as ResponseCodeV2
from iso15118.shared.messages.iso15118_2.datatypes import (
    SalesTariff,
    SalesTariffEntry,
    SAScheduleTuple,
    SubCertificates,
)
from iso15118.shared.messages.iso15118_2.header import MessageHeader as MessageHeaderV2
from iso15118.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from iso15118.shared.messages.iso15118_20.ac import (
    ACChargeParameterDiscoveryResParams,
    BPTACChargeParameterDiscoveryResParams,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    AbsolutePriceSchedule,
    AdditionalService,
    AdditionalServiceList,
    ChargingSchedule,
    DynamicScheduleExchangeResParams,
    OverstayRule,
    OverstayRuleList,
    Parameter,
    ParameterSet,
    PowerSchedule,
    PowerScheduleEntry,
    PowerScheduleEntryList,
    PriceLevelSchedule,
    PriceLevelScheduleEntry,
    PriceLevelScheduleEntryList,
    PriceRule,
    PriceRuleStack,
    PriceRuleStackList,
    ProviderID,
    ScheduledScheduleExchangeResParams,
    ScheduleExchangeReq,
    ScheduleTuple,
    SelectedEnergyService,
    Service,
    ServiceList,
    ServiceParameterList,
    TaxRule,
    TaxRuleList,
)
from iso15118.shared.messages.iso15118_20.common_types import EVSEStatus
from iso15118.shared.messages.iso15118_20.common_types import MeterInfo as MeterInfoV20
from iso15118.shared.messages.iso15118_20.common_types import RationalNumber
from iso15118.shared.messages.iso15118_20.common_types import (
    ResponseCode as ResponseCodeV20,
)
from iso15118.shared.messages.iso15118_20.dc import (
    BPTDCChargeParameterDiscoveryResParams,
    DCChargeParameterDiscoveryResParams,
)
from iso15118.shared.security import (
    CertPath,
    KeyEncoding,
    KeyPasswordPath,
    KeyPath,
    create_signature,
    encrypt_priv_key,
    get_cert_cn,
    load_cert,
    load_priv_key,
)
from iso15118.shared.states import State

from iso15118.shared.settings import set_pki_protocol

######### iso15118module main.py imports ##########################
from iso15118.secc import SECCHandler

from iso15118.secc.controller.interface import ServiceStatus
from iso15118.secc.secc_settings import Config
from iso15118.shared.exificient_exi_codec import ExificientEXICodec

from iso15118.shared.utils import cancel_task

SECC_CommSetup_Timeout = 18 # [V2G2-605]

##################################################################################################################################################################################################################
class ISO15118_Handler(IEC61851_Handler): #EVSEControllerInterface from Ecog-io
    #======================== ISO Specific Variables =====================#
    slac_handler: Slac_Handler #Slac handler that will process all slac operations (made taking into account Ecog-io example)
    secc_handler: SECCHandler #SECC handler control center that manages all hlc communication sessions (Ecog-io)
    #============================ Class Functions ==========================#
    def __init__(self, authentication_needed):
        try:
            #calls parent's classes initialization
            IEC61851_Handler.__init__(self, authentication_needed)

            #======================================SLAC initialization====================================#
            self.evse_id = os.getenv("EVSE_ID")
            
            self.slac_handler = Slac_Handler(self.evse_id)
            self.slac_handler_task = None

            self.secc_comm_status_timer_task = None
            self.secc_comm_status = None
            logger.info("########################################### Finished ISO Handler initialization ###########################################")
        except Exception as e:
            logger.error(e)
            exit(1)

    async def hlc_check_unplug(self):
        if self.cp_state.present[0] == 'A': # Car unplugged
                if self.slac_handler.level_communication != COMMUNICATION_UNDEFINED:
                    logger.debug("Reseting hlc parameters duo to unplug")
                    if self.slac_handler_task:
                        await cancel_task(self.slac_handler_task)
                    await self.reset_hlc() # Reset hlc parameters

    async def comm_setup_timer(self):
        """ 
        [V2G2-716] The SECC shall stop waiting for SessionSetupReq and stop monitoring the V2G_SECC_CommunicationSetup_Timer
        when V2G_SECC_CommunicationSetup_Timer is equal or larger than V2G_SECC_CommunicationSetup_Performance_Time
        and no SessionSetupRes message was sent. It shall then apply [V2G2-034].
        """
        try:
            logger.debug(f"Monitoring V2G Communication Setup Time; initial comm_status: {self.secc_comm_status}")
            await asyncio.sleep(SECC_CommSetup_Timeout)
            logger.warning(f"V2G SECC Communication Setup Timeout; Resuming LLC Communication")
            self.secc_comm_status = False

        except asyncio.CancelledError:
            logger.debug("HLC timer was cancelled before completion.")

    async def hlc_check_comm(self):
        """
        This method might also be used by the EVSE to terminate HLC communication and fallback to LLC
        """
        try:
            if self.secc_comm_status == False and self.slac_handler.level_communication != COMMUNICATION_LLC:
                await self.reset_hlc(fallback = True)
                await self.slac_handler.reinit_cp(cp_controller=self.basicCharging, fallback=True)

            elif self.secc_comm_status == True:
                if self.slac_handler.level_communication != COMMUNICATION_HLC:
                    self.slac_handler.level_communication = COMMUNICATION_HLC # definitive HLC communication

                if self.secc_comm_status_timer_task:
                    await cancel_task(self.secc_comm_status_timer_task)

        except Exception as e:
            logger.error(f"Exception in communication check: {e}")

    async def hlc_track_connection(self):
        logger.info("Starting hlc connection tracking...")
        while True:
            try:
                if self.slac_handler.level_communication == COMMUNICATION_UNDEFINED:        # No Communication type determined yet
                    if self.cp_state.present[0] == 'B':                                     # Car plugged 
                        if self.slac_handler_task == None or self.slac_handler_task.done(): # if SLAC not done yet, or not started
                            self.slac_handler_task = asyncio.create_task(self.slac_handler.handling(self.basicCharging))

                elif self.slac_handler.level_communication == COMMUNICATION_HLC_READY:
                    if self.secc_comm_status_timer_task == None or self.secc_comm_status_timer_task.done():
                        self.secc_comm_status_timer_task = asyncio.create_task(self.comm_setup_timer())

                await self.hlc_check_unplug()
                await self.hlc_check_comm()
                await asyncio.sleep(1)
            except Exception as e:
                logger.error(f"hlc error: {e}")

    async def reset_hlc(self, fallback: bool = False):
        try:
            logger.info("Reseting hlc values")
            self.slac_handler.slac_running_session.reset()   # Reset slac session
            self.slac_handler.slac_attempt = 0 # Restart slac attempt counter
            self.basicCharging.charge_mode = ChargeMode.DISABLED # Make sure charger is in stop mode
            self.basicCharging.hlc_charging = 0 # Deactivate hlc charging 
            self.secc_comm_status_timer_task = None

            if fallback == True:
                self.slac_handler.level_communication = COMMUNICATION_LLC # Fallback to LLC Communication
                self.secc_comm_status = False
            else:
                self.slac_handler.level_communication = COMMUNICATION_UNDEFINED # Session finished, communication level defined as 'undetermined' for next session
                self.secc_comm_status = None

        except Exception as e:
            logger.error(e)

    #overwrites IEC61851 run method
    async def run(self):
        try:
            logger.info("Starting iso handler run...")
            routinesTask = asyncio.create_task(self.mainRoutines())
            backgroundTask = asyncio.create_task(self.backgroundChecks())
            slacProcessTask = asyncio.create_task(self.hlc_track_connection()) # start hlc routine
        except Exception as e:
            logger.error(e)
