##########################################################################################################################################################################################
import asyncio
import os

############################################################################### IEC Charger Class #######################################################################################
from evse.iec61851 import IEC61851_Handler

############################################################################### SLAC ####################################################################################################
from evse.hlc.slac_handler import SlacHandler

from pyslac.enums import (
    COMMUNICATION_HLC,
    COMMUNICATION_LLC,
    COMMUNICATION_NONE)

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
5
from iso15118.shared.utils import cancel_task

##################################################################################################################################################################################################################
class ISO15118_Handler(IEC61851_Handler): #EVSEControllerInterface from Ecog-io
    #======================== ISO Specific Variables =====================#
    slac_handler: SlacHandler #Slac handler that will process all slac operations (made taking into account Ecog-io example)
    secc_handler: SECCHandler #SECC handler control center that manages all hlc communication sessions (Ecog-io)
    #============================ Class Functions ==========================#
    def __init__(self, authentication_needed):
        try:
            #calls parent's classes initialization
            IEC61851_Handler.__init__(self, authentication_needed)

            #======================================SLAC initialization====================================#
            self.evse_id = os.getenv("EVSE_ID")
            
            self.slac_handler=SlacHandler(self.evse_id)

            logger.info("########################################### Finished ISO Handler initialization ###########################################")
        except Exception as e:
            logger.error(e)
            exit(1)

    async def track_hlc_connection(self):
        while True:
            try:
                # No Communication type determined yet
                if self.slac_handler.level_communication == COMMUNICATION_NONE:  # SLAC not determined yet
                    if self.cp_state.present[0] == "B":  # Car plugged
                        logger.debug("STARTING SLAC HANDLING")
                        await self.slac_handler.handling(self.basicCharging)  
                
                else:
                    if self.cp_state.present[0] == 'A':  # Car unplugged and SLAC not reset yet
                        logger.debug("RESETTING SLAC PARAMETERS AFTER UNPLUG")
                        await self.reset_hlc()
                        
                await asyncio.sleep(0.1)
            except Exception as e:
                logger.error(f"hlc error: {e}")

    async def reset_hlc(self):
        try:
            logger.info("Reseting SLAC values")
            self.slac_handler.slac_running_session.reset()   # Reset slac session
            self.slac_handler.level_communication = COMMUNICATION_NONE # Session finished, communication level defined as 'undetermined' for next session
            self.slac_handler.slac_attempt = 0 # Restart slac attempt counter
            self.basicCharging.charge_mode = 1 # Make sure charger is in stop mode
            self.basicCharging.hlc_charging = 0 # Deactivate hlc charging 

            # #close iso15118 module session, ver isto melhor depois
            # if self.secc_handler.tcp_server_handler:
            #     try:
            #         logger.debug("Making sure existing tcp server handler is terminated duo to EV Unplug")
            #         await cancel_task(self.secc_handler.tcp_server_handler)
            #     except Exception as e:
            #         logger.warning(f"Error cancelling existing tcp server handler directly from EVSE: {e}")

        except Exception as e:
            logger.error(e)

    #overwrites IEC61851 run method
    async def run(self):
        try:
            logger.info("############################################################ STARTING EVSE TASKS ################################################################")
            routinesTask = asyncio.create_task(self.mainRoutines())
            backgroundTask = asyncio.create_task(self.backgroundChecks())
            slacProcessTask = asyncio.create_task(self.track_hlc_connection()) # start hlc routine
        except Exception as e:
            logger.error(e)
