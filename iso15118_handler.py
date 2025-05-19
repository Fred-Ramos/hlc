##########################################################################################################################################################################################
import asyncio
import os

############################################################################### IEC Charger Class #######################################################################################
from evse.iec61851 import IEC61851_Handler

############################################################################### SLAC ####################################################################################################
from evse.hlc.slac_handler import SlacHandler

from pyslac.enums import (
    HLC_SUCESS,
    LLC_COM,
    HLC_NO_LINK)

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

##################################################################################################################################################################################################################
class ISO15118_Handler(IEC61851_Handler, EVSEControllerInterface): #EVSEControllerInterface from Ecog-io
    #======================== ISO Specific Variables =====================#
    slac_handler: SlacHandler #Slac handler that will process all slac operations (made taking into account Ecog-io example)
    secc_handler: SECCHandler #SECC handler control center that manages all hlc communication sessions (Ecog-io)
    #============================ Class Functions ==========================#
    def __init__(self):
        try:
            #calls parent's classes initialization
            IEC61851_Handler.__init__(self)
            EVSEControllerInterface.__init__(self)

            #======================================SLAC initialization====================================#
            self.evse_id = os.getenv("EVSE_ID")
            
            self.slac_handler=SlacHandler(self.evse_id)
            #===============================ISO15118 MODULE initialization================================#
            """
            Entrypoint function that starts the ISO 15118 code running on
            the SECC (Supply Equipment Communication Controller)
            """
            logger.info("Starting (INESCTEC Modified) EcoG-io's EVSEController")
            self.ev_data_context = EVDataContext()
            self.evse_data_context = get_evse_context()

            self.iso_config = Config()
            self.iso_config.load_envs()
            self.iso_config.print_settings()

            
            self.secc_handler = SECCHandler(
                exi_codec=ExificientEXICodec(),
                evse_controller=self,
                config=self.iso_config,
            )

            self.meter_id = 'INESCTEC_AC_1ph_meter'

            logger.info("########################################### Finished ISO Charger structure initialization ###########################################")
        except Exception as e:
            logger.error(e)
            exit(1)

    async def track_hlc_connection(self):
        while True:
            try:
                if self.slac_handler.level_communication == HLC_NO_LINK:  # SLAC not determined yet
                    if self.cp_state.present[0] == "B":  # Car plugged
                        logger.debug("STARTING SLAC HANDLING")
                        await self.slac_handler.handling(self.basicCharging)  
                elif self.slac_handler.level_communication != HLC_NO_LINK and self.cp_state.present[0] == 'A':   # Car unplugged and SLAC not reset yet
                    logger.debug("RESETTING SLAC PARAMETERS AFTER UNPLUG")
                    await self.reset_hlc()
                    
                    #close iso15118 module session, ver isto melhor depois
                    if self.secc_handler.tcp_server_handler:
                        try:
                            logger.debug("Making sure existing tcp server handler is terminated duo to EV Unplug")
                            await cancel_task(self.secc_handler.tcp_server_handler)
                        except Exception as e:
                            logger.warning(f"Error cancelling existing tcp server handler directly from EVSE: {e}")

                await asyncio.sleep(0.1)
            except Exception as e:
                logger.error(f"hlc error: {e}")

    async def reset_hlc(self):
        try:
            logger.info("Reseting SLAC values")
            self.slac_handler.slac_running_session.reset()   # Reset slac session
            self.slac_handler.level_communication = HLC_NO_LINK # Session finished, communication level defined as 'undetermined' for next session
            self.slac_handler.slac_attempt = 0 # Restart slac attempt counter
            self.basicCharging.charge_mode = 1 # Make sure charger is in stop mode
            self.basicCharging.hlc_charging = 0 # Deactivate hlc charging 
        except Exception as e:
            logger.error(e)

    #overwrites IEC61851 run method
    async def run(self):
        try:
            logger.info("############################################################ STARTING EVSE TASKS ################################################################")
            await self.set_status(ServiceStatus.STARTING)              # set ecogio status
            routinesTask = asyncio.create_task(self.callAllRoutines()) # start routines as in IEC61851
            slacProcessTask = asyncio.create_task(self.track_hlc_connection()) # start hlc routine
            seccHandlerTask = asyncio.create_task(self.secc_handler.start(self.iso_config.iface))  # SECC entry point
        except Exception as e:
            logger.error(e)

    ##########################################ISO EXPERIMENTAL#####################################################
    # From now on there are the addition of the methods of the ISO15118 module by EcoG-io                         #
    # They were originally part of SimEVSEController which inherits from EVSEControllerInterface abstract methods #
    ###############################################################################################################

    def reset_ev_data_context(self):
        logger.info("Reseting EV data context")
        self.ev_data_context = EVDataContext()

    # ============================================================================
    # |             COMMON FUNCTIONS (FOR ALL ENERGY TRANSFER MODES)             |
    # ============================================================================
    async def set_status(self, status: ServiceStatus) -> None:
        logger.debug(f"New Status: {status}")


    def set_selected_protocol(self, protocol: Protocol) -> None:
        """Set the selected Protocol.

        Args:
            protocol: An EV communication protocol supported by Josev.
        """
        self._selected_protocol = protocol

        set_pki_protocol(protocol)
    
    async def get_evse_id(self, protocol: Protocol) -> str:
        if protocol == Protocol.DIN_SPEC_70121:
            #  To transform a string-based DIN SPEC 91286 EVSE ID to hexBinary
            #  representation and vice versa, the following conversion rules shall
            #  be used for each character and hex digit: '0' <--> 0x0, '1' <--> 0x1,
            #  '2' <--> 0x2, '3' <--> 0x3, '4' <--> 0x4, '5' <--> 0x5, '6' <--> 0x6,
            #  '7' <--> 0x7, '8' <--> 0x8, '9' <--> 0x9, '*' <--> 0xA,
            #  Unused <--> 0xB .. 0xF.
            # Example: The DIN SPEC 91286 EVSE ID “49*89*6360” is represented
            # as “0x49 0xA8 0x9A 0x63 0x60”.
            return "49A89A6360"
        """Overrides EVSEControllerInterface.get_evse_id()."""
        return self.evse_id

    async def get_supported_energy_transfer_modes(
        self, protocol: Protocol
    ) -> List[EnergyTransferModeEnum]:
        """Overrides EVSEControllerInterface.get_supported_energy_transfer_modes()."""
        if protocol == Protocol.DIN_SPEC_70121:
            """
            For DIN SPEC, only DC_CORE and DC_EXTENDED are supported.
            The other DC modes DC_COMBO_CORE and DC_DUAL are out of scope for DIN SPEC
            """
            dc_extended = EnergyTransferModeEnum.DC_EXTENDED
            return [dc_extended]

        # It's not valid to have mixed energy transfer modes associated with
        # a single EVSE. Providing this here only for simulation purposes.
        ac_single_phase = EnergyTransferModeEnum.AC_SINGLE_PHASE_CORE
        # ac_three_phase = EnergyTransferModeEnum.AC_THREE_PHASE_CORE
        # dc_extended = EnergyTransferModeEnum.DC_EXTENDED
        return [ac_single_phase]

    # ISO 15118-20 EXCLUSIVE
    # Check control mode, get respective parameters for ScheduleExchangeRes.
    # If control mode is Scheduled, return ScheduledScheduleExchangeResParams.
    # If control mode is Dynamic, return DynamicScheduleExchangeResParams.
    async def get_schedule_exchange_params(
        self,
        selected_energy_service: SelectedEnergyService,
        control_mode: ControlMode,
        schedule_exchange_req: ScheduleExchangeReq,
    ) -> Union[ScheduledScheduleExchangeResParams, DynamicScheduleExchangeResParams]:
        if control_mode == ControlMode.SCHEDULED:
            return await self.get_scheduled_se_params(
                selected_energy_service, schedule_exchange_req
            )
        else:
            return await self.get_dynamic_se_params(
                selected_energy_service, schedule_exchange_req
            )

    # ISO 15118-20 EXCLUSIVE
    async def get_scheduled_se_params(
        self,
        selected_energy_service: SelectedEnergyService,
        schedule_exchange_req: ScheduleExchangeReq,
    ) -> ScheduledScheduleExchangeResParams:
        """Overrides EVSEControllerInterface.get_scheduled_se_params()."""

        logger.warning(
            f"GET_SCHEDULED_SE_PARAMS: Called with arguments:\n"
            f"selected_energy_service:\n"
            f"  service_id: {selected_energy_service.service.id}\n"
            f"  parameter_set_id: {selected_energy_service.parameter_set.id}\n"
            f"schedule_exchange_req:\n"
            f"  maximum_supporting_points: {schedule_exchange_req.max_supporting_points}\n"
            f"  control_mode: "
            f"{'Dynamic' if schedule_exchange_req.dynamic_params is not None else 'Scheduled'}\n"
            f"  departure_time: "
            f"{(schedule_exchange_req.dynamic_params or schedule_exchange_req.scheduled_params).departure_time}\n"
            f"  target_energy_request: "
            f"{(schedule_exchange_req.dynamic_params or schedule_exchange_req.scheduled_params).ev_target_energy_request}\n"
            f"  maximum_energy_request: "
            f"{(schedule_exchange_req.dynamic_params or schedule_exchange_req.scheduled_params).ev_max_energy_request}\n"
            f"  minimum_energy_request: "
            f"{(schedule_exchange_req.dynamic_params or schedule_exchange_req.scheduled_params).ev_min_energy_request}\n"
        )

        charging_power_schedule_entry = PowerScheduleEntry(
            duration=3600,
            power=RationalNumber(exponent=3, value=10),
            # Check if AC ThreePhase applies (Connector parameter within parameter set
            # of SelectedEnergyService) if you want to add power_l2 and power_l3 values
        )

        charging_power_schedule = PowerSchedule(
            time_anchor=0,
            available_energy=RationalNumber(exponent=3, value=300),
            power_tolerance=RationalNumber(exponent=0, value=2000),
            schedule_entry_list=PowerScheduleEntryList(
                entries=[charging_power_schedule_entry]
            ),
        )

        tax_rule = TaxRule(
            tax_rule_id=1,
            tax_rule_name="What a great tax rule name",
            tax_rate=RationalNumber(exponent=0, value=10),
            tax_included_in_price=False,
            applies_to_energy_fee=True,
            applies_to_parking_fee=True,
            applies_to_overstay_fee=True,
            applies_to_min_max_cost=True,
        )

        tax_rules = TaxRuleList(tax_rule=[tax_rule])

        price_rule = PriceRule(
            energy_fee=RationalNumber(exponent=0, value=20),
            parking_fee=RationalNumber(exponent=0, value=0),
            parking_fee_period=0,
            carbon_dioxide_emission=0,
            renewable_energy_percentage=0,
            power_range_start=RationalNumber(exponent=0, value=0),
        )

        price_rule_stack = PriceRuleStack(duration=3600, price_rules=[price_rule])

        price_rule_stacks = PriceRuleStackList(price_rule_stacks=[price_rule_stack])

        overstay_rule = OverstayRule(
            description="What a great description",
            start_time=0,
            fee=RationalNumber(exponent=0, value=50),
            fee_period=3600,
        )

        overstay_rules = OverstayRuleList(
            time_threshold=3600,
            power_threshold=RationalNumber(exponent=3, value=30),
            rules=[overstay_rule],
        )

        additional_service = AdditionalService(
            service_name="What a great service name",
            service_fee=RationalNumber(exponent=0, value=0),
        )

        additional_services = AdditionalServiceList(
            additional_services=[additional_service]
        )

        charging_absolute_price_schedule = AbsolutePriceSchedule(
            time_anchor=0,
            schedule_id=1,
            currency="EUR",
            language="ENG",
            price_algorithm=PriceAlgorithm.POWER,
            min_cost=RationalNumber(exponent=0, value=1),
            max_cost=RationalNumber(exponent=0, value=10),
            tax_rules=tax_rules,
            price_rule_stacks=price_rule_stacks,
            overstay_rules=overstay_rules,
            additional_services=additional_services,
        )

        discharging_power_schedule_entry = PowerScheduleEntry(
            duration=3600,
            power=RationalNumber(exponent=3, value=10),
            # Check if AC ThreePhase applies (Connector parameter within parameter set
            # of SelectedEnergyService) if you want to add power_l2 and power_l3 values
        )

        discharging_power_schedule = PowerSchedule(
            time_anchor=0,
            schedule_entry_list=PowerScheduleEntryList(
                entries=[discharging_power_schedule_entry]
            ),
        )

        discharging_absolute_price_schedule = charging_absolute_price_schedule

        charging_schedule = ChargingSchedule(
            power_schedule=charging_power_schedule,
            absolute_price_schedule=charging_absolute_price_schedule,
        )

        discharging_schedule = ChargingSchedule(
            power_schedule=discharging_power_schedule,
            absolute_price_schedule=discharging_absolute_price_schedule,
        )

        schedule_tuple = ScheduleTuple(
            schedule_tuple_id=1,
            charging_schedule=charging_schedule,
            discharging_schedule=discharging_schedule,
        )

        scheduled_params = ScheduledScheduleExchangeResParams(
            schedule_tuples=[schedule_tuple]
        )

        return scheduled_params

    # ISO 15118-20 EXCLUSIVE
    async def get_service_parameter_list(self, service_id: int) -> Optional[ServiceParameterList]:
        """Overrides EVSEControllerInterface.get_service_parameter_list()."""
        parameter_sets_list: List[ParameterSet] = []

        try:
            # === Parameters from ISO 15118-20 Table 206 (AC BPT Service) ===

            # 1: SinglePhase | 2: ThreePhase
            connector_parameter = Parameter(name="Connector", int_value=1)

            # 1: Scheduled | 2: Dynamic

            # According to the spec, both EVSE and EV must offer Scheduled = 1 and
            # Dynamic = 2 control modes
            # As the EVCC Simulator will choose the first parameter set by default,
            # we first advertise the one with Dynamic control mode 2
            # The env variable 15118_20_PRIORITIZE_DYNAMIC_CONTROL_MODE is provided
            # if this is to be inverted. When set, the first parameter set will be for
            # scheduled control mode. This will be removed soon. For testing purposes
            # only.

            # [V2G20-2663]:The SECC shall only offer MobilityNeedsMode equal
                    # to ‘2’ when ControlMode is set to ‘2’ (Dynamic).
                    # So, for Dynamic mode the MobilityNeeds can have the value
                    # of 1 or 2 so in this if clause we insert another parameter set
                    # for Dynamic mode but for MobilityNeedsMode = 1 (MobilityNeeds
                    # provided by the EVCC).
            control_mode_parameter = Parameter(name="ControlMode", int_value=1)

            # Voltage in V (0 to 500)
            nominal_voltage_parameter = Parameter(name="EVSENominalVoltage", int_value=self.nominalMaxVoltage)

            # 1: Provided by EVCC | 2: SECC allowed
            mobility_needs_parameter = Parameter(name="MobilityNeedsMode", int_value=1)

            # 0: No pricing | 1: Absolute | 2: Price Levels
            pricing_parameter = Parameter(name="Pricing", int_value=0)

            # 1: Unified | 2: Separated
            bpt_channel_parameter = Parameter(name="BPTChannel", int_value=1)

            # 1: GridFollowing | 2: GridForming
            generator_mode_parameter = Parameter(name="GeneratorMode", int_value=1)

            # 1: ActiveDetection | 2: PassiveDetection
            islanding_detection_parameter = Parameter(name="GridCodeIslandingDetectionMethod", int_value=1)

            # === Compose all parameters into a single ParameterSet ===
            parameters_list = [
                connector_parameter,
                control_mode_parameter,
                nominal_voltage_parameter,
                mobility_needs_parameter,
                pricing_parameter,
                bpt_channel_parameter,
                generator_mode_parameter,
                islanding_detection_parameter,
            ]

            parameter_set = ParameterSet(id=1, parameters=parameters_list)
            parameter_sets_list.append(parameter_set)

        except AttributeError as e:
            logger.error(f"No ServiceParameterList available for service ID {service_id}")
            raise e

        return ServiceParameterList(parameter_sets=parameter_sets_list)

    # ISO 15118-20 EXCLUSIVE
    async def get_dynamic_se_params(
        self,
        selected_energy_service: SelectedEnergyService,
        schedule_exchange_req: ScheduleExchangeReq,
    ) -> DynamicScheduleExchangeResParams:
        """Overrides EVSEControllerInterface.get_dynamic_se_params()."""
        price_level_schedule_entry = PriceLevelScheduleEntry(
            duration=3600, price_level=1
        )

        schedule_entries = PriceLevelScheduleEntryList(
            entries=[price_level_schedule_entry]
        )

        price_level_schedule = PriceLevelSchedule(
            id="id1",
            time_anchor=0,
            schedule_id=1,
            schedule_description="What a great description",
            num_price_levels=1,
            schedule_entries=schedule_entries,
        )

        dynamic_params = DynamicScheduleExchangeResParams(
            departure_time=7200,
            min_soc=30,
            target_soc=80,
            price_level_schedule=price_level_schedule,
        )

        return dynamic_params

    async def get_energy_service_list(self) -> ServiceList:
        """Overrides EVSEControllerInterface.get_energy_service_list()."""
        # AC = 1, DC = 2, AC_BPT = 5, DC_BPT = 6;
        # DC_ACDP = 4 and DC_ADCP_BPT NOT supported

        current_protocol = self.get_selected_protocol()
        if current_protocol == Protocol.ISO_15118_20_DC:
            service_ids = [2, 6]
        elif current_protocol == Protocol.ISO_15118_20_AC:
            service_ids = [1, 5]

        service_list: ServiceList = ServiceList(services=[])
        for service_id in service_ids:
            service_list.services.append(
                Service(service_id=service_id, free_service=False)
            )

        return service_list

    def is_eim_authorized(self) -> bool:
        """Overrides EVSEControllerInterface.is_eim_authorized()."""
        return False

    async def is_authorized(
        self,
        id_token: Optional[str] = None,
        id_token_type: Optional[AuthorizationTokenType] = None,
        certificate_chain: Optional[bytes] = None,
        hash_data: Optional[List[Dict[str, str]]] = None,
    ) -> AuthorizationResponse:
        """Overrides EVSEControllerInterface.is_authorized()."""
        protocol = self.get_selected_protocol()
        response_code: Optional[
            Union[ResponseCodeDINSPEC, ResponseCodeV2, ResponseCodeV20]
        ] = None
        if protocol == Protocol.DIN_SPEC_70121:
            response_code = ResponseCodeDINSPEC.OK
        elif protocol == Protocol.ISO_15118_20_COMMON_MESSAGES:
            response_code = ResponseCodeV20.OK
        else:
            response_code = ResponseCodeV2.OK

        return AuthorizationResponse(
            authorization_status=AuthorizationStatus.ACCEPTED,
            certificate_response_status=response_code,
        )

    async def get_sa_schedule_list_dinspec(
        self, max_schedule_entries: Optional[int], departure_time: int = 0
    ) -> Optional[List[SAScheduleTupleEntryDINSPEC]]:
        logger.warning("Not supported for now, commented code")
        pass
        # """Overrides EVSEControllerInterface.get_sa_schedule_list_dinspec()."""
        # sa_schedule_list: List[SAScheduleTupleEntryDINSPEC] = []
        # entry_details = PMaxScheduleEntryDetailsDINSPEC(
        #     p_max=200, time_interval=RelativeTimeIntervalDINSPEC(start=0, duration=3600)
        # )
        # p_max_schedule_entries = [entry_details]
        # pmax_schedule_entry = PMaxScheduleEntryDINSPEC(
        #     p_max_schedule_id=0, entry_details=p_max_schedule_entries
        # )

        # sa_schedule_tuple_entry = SAScheduleTupleEntryDINSPEC(
        #     sa_schedule_tuple_id=1,
        #     p_max_schedule=pmax_schedule_entry,
        #     sales_tariff=None,
        # )
        # sa_schedule_list.append(sa_schedule_tuple_entry)
        # return sa_schedule_list

    async def get_sa_schedule_list(
        self,
        ev_data_context: EVDataContext,
        is_free_charging_service: bool,
        max_schedule_entries: Optional[int],
        departure_time: int = 0,
    ) -> Optional[List[SAScheduleTuple]]:
        """
        Generates a list of SAScheduleTuple objects based on the EV's data context
        and the provided departure time. Divides the time into 3 equal parts.

        Args:
            ev_data_context (EVDataContext): Context data about the EV and charging limits.
            is_free_charging_service (bool): Indicates if the service is free.
            max_schedule_entries (Optional[int]): Maximum allowed schedule entries.
            departure_time (int): Time in seconds until departure. Defaults to 24 hours if 0.

        Returns:
            Optional[List[SAScheduleTuple]]: List of SAScheduleTuple objects.
        """
        logger.warning(f"GET_SA_SCHEDULE_LIST: EVDataContext attributes:\n"
               f"evcc_id: {ev_data_context.evcc_id}\n"
               f"rated_limits: {vars(ev_data_context.rated_limits)}\n"
               f"session_limits: {vars(ev_data_context.session_limits)}\n"
               f"departure_time: {ev_data_context.departure_time}\n"
               f"target_energy_request: {ev_data_context.target_energy_request}\n"
               f"target_soc: {ev_data_context.target_soc}\n"
               f"total_battery_capacity: {ev_data_context.total_battery_capacity}\n"
               f"max_energy_request: {ev_data_context.max_energy_request}\n"
               f"min_energy_request: {ev_data_context.min_energy_request}\n"
               f"min_soc: {ev_data_context.min_soc}\n"
               f"max_soc: {ev_data_context.max_soc}\n"
               f"max_v2x_energy_request: {ev_data_context.max_v2x_energy_request}\n"
               f"min_v2x_energy_request: {ev_data_context.min_v2x_energy_request}\n"
               f"remaining_time_to_target_soc: {ev_data_context.remaining_time_to_target_soc}\n"
               f"remaining_time_to_max_soc: {ev_data_context.remaining_time_to_max_soc}\n"
               f"remaining_time_to_min_soc: {ev_data_context.remaining_time_to_min_soc}\n"
               f"bulk_soc: {ev_data_context.bulk_soc}\n"
               f"remaining_time_to_bulk_soc: {ev_data_context.remaining_time_to_bulk_soc}\n"
               f"present_soc: {ev_data_context.present_soc}\n"
               f"present_voltage: {ev_data_context.present_voltage}\n"
               f"present_active_power: {ev_data_context.present_active_power}\n"
               f"present_active_power_l2: {ev_data_context.present_active_power_l2}\n"
               f"present_active_power_l3: {ev_data_context.present_active_power_l3}\n"
               f"present_reactive_power: {ev_data_context.present_reactive_power}\n"
               f"present_reactive_power_l2: {ev_data_context.present_reactive_power_l2}\n"
               f"present_reactive_power_l3: {ev_data_context.present_reactive_power_l3}\n"
               f"target_current: {ev_data_context.target_current}\n"
               f"target_voltage: {ev_data_context.target_voltage}\n"
               f"selected_energy_mode: {ev_data_context.selected_energy_mode}\n"
               f"REMAINING ARGUMENTS\n"
               f"max_schedule_entries={max_schedule_entries}, departure_time={departure_time}")
        
        if departure_time == 0:
            departure_time = 86400

        sa_schedule_list: List[SAScheduleTuple] = []

        #number of schedules we want to do
        n_wanted_entries = 20 #max number of sascheduletuple elements without GIVING EOF PROBLEMS

        power_levels = [[3, 5, 2], [3, 4, 3], [2, 3, 4]]
        price_levels = [[1, 2, 3], [1, 2, 3], [1, 2, 3]]
        n_typed_schedules = len(power_levels)
        n_wanted_schedules = n_typed_schedules #we want the same number of schedules
        for i in range(n_wanted_schedules):
            sales_tariff_entries: List[SalesTariffEntry] = []
            pmax_schedule_entries: List[PMaxScheduleEntry] = []

            relative_time = [int(k * departure_time / n_wanted_entries) for k in range(n_wanted_entries + 1)]

            n_typed_schedules = len(power_levels)
            for j in range(n_wanted_entries):
                power_level = power_levels[i][j % len(power_levels[i])]
                price_level = price_levels[i][j % len(price_levels[i])]

                #calculate duration
                duration=relative_time[j+1]-relative_time[j]
                #make simulated pmax entry
                pmax_schedule_entry = PMaxScheduleEntry(
                    p_max=PVPMax(value=power_level, multiplier=3, unit=UnitSymbol.WATT),
                    time_interval=RelativeTimeInterval(start=relative_time[j], duration=duration),
                )
                #make simulated salestariff entry
                sales_tariff_entry = SalesTariffEntry(
                    e_price_level=price_level,
                    time_interval=RelativeTimeInterval(start=relative_time[j], duration=duration),
                )
                #append entries
                pmax_schedule_entries.append(pmax_schedule_entry)
                sales_tariff_entries.append(sales_tariff_entry)
            
            #after all entries made, create shedule and tariff
            p_max_schedule = PMaxSchedule(schedule_entries=pmax_schedule_entries)
            sales_tariff = SalesTariff(
                                id=f"testTariff{i}",                                       #optional field, broadly used for message-level identification and signing
                                sales_tariff_id=i+1,                                       #Valid values from 1 to 255. unique identifier for tariff during a charging session. identifies the tariff within the context of a charging session
                                sales_tariff_description = f"Testing Sales Tariffs '{i}'", #optional field, describes the tariff
                                sales_tariff_entry=sales_tariff_entries,
                                num_e_price_levels=len(sales_tariff_entries),
                            )
            # Putting the list of SAScheduleTuple entries together
            sa_schedule_tuple = SAScheduleTuple(
                sa_schedule_tuple_id=i+1,  #Valid values from 1 to 255
                p_max_schedule=p_max_schedule,
                sales_tariff=None if is_free_charging_service else sales_tariff,
            )
            sa_schedule_list.append(sa_schedule_tuple)

            # TODO We could also implement an optional SalesTariff, but for the sake of
            #      time we'll do that later (after the basics are implemented).
            #      When implementing the SalesTariff, we also need to apply a digital
            #      signature to it.

            # TODO We need to take care of [V2G2-741], which says that the SECC needs to
            #      resend a previously agreed SAScheduleTuple and the "period of time
            #      this SAScheduleTuple applies for shall be reduced by the time already
            #      elapsed".

       
        #print out the available schedules
        # for sa_schedule in sa_schedule_list:
        #     logger.warning("Generated SA Schedule Tuple:\n"
        #                 f"  SA Schedule Tuple ID: {sa_schedule.sa_schedule_tuple_id}\n"
        #                 f"  PMaxSchedule:\n"
        #                 f"    Entries:\n"
        #                 + "\n".join(
        #                     [f"      - PMax: {entry.p_max.value} {entry.p_max.unit.value}, "
        #                         f"Start: {entry.time_interval.start}, "
        #                         f"Duration: {entry.time_interval.duration}" for entry in sa_schedule.p_max_schedule.schedule_entries]
        #                 ) + "\n"
        #                 f"  SalesTariff:\n"
        #                 f"    ID: {sa_schedule.sales_tariff.id if sa_schedule.sales_tariff else 'None'}\n"
        #                 f"    Number of Price Levels: {sa_schedule.sales_tariff.num_e_price_levels if sa_schedule.sales_tariff else 'None'}\n"
        #                 f"    Entries:\n"
        #                 + ("\n".join(
        #                     [f"      - Price Level: {entry.e_price_level}, "
        #                         f"Start: {entry.time_interval.start}, "
        #                         f"Duration: {entry.time_interval.duration}" for entry in sa_schedule.sales_tariff.sales_tariff_entry]
        #                 ) if sa_schedule.sales_tariff else '      None')
        #                 )
        return sa_schedule_list


    async def get_meter_info_v2(self) -> MeterInfoV2:
        """Overrides EVSEControllerInterface.get_meter_info_v2()."""
        return MeterInfoV2(
            meter_id=self.meter_id, 
            meter_reading=int(self.energyMeter.energy), 
            t_meter=time.time()  #substituir por em.energy depois
        )

    async def get_meter_info_v20(self) -> MeterInfoV20:
        """Overrides EVSEControllerInterface.get_meter_info_v20()."""
        return MeterInfoV20(
            meter_id=self.meter_id,
            charged_energy_reading_wh=int(self.energyMeter.energy),
            meter_timestamp=time.time(),
        )

    async def get_supported_providers(self) -> Optional[List[ProviderID]]:
        """Overrides EVSEControllerInterface.get_supported_providers()."""
        logger.debug("Getting supported providers")
        return None

    async def set_hlc_charging(self, is_ongoing: bool) -> None:
        """Overrides EVSEControllerInterface.set_hlc_charging()."""
        logger.debug("Setting hlc charging")
        pass

    async def stop_charger(self) -> None:
        logger.debug("Stopping charging")
        pass

    async def get_cp_state(self) -> CpState:
        """Overrides EVSEControllerInterface.set_cp_state()."""
        logger.info(f"getting CP STATE {self.basicCharging.committed_state}")
        return self.basicCharging.committed_state

    async def service_renegotiation_supported(self) -> bool:
        """Overrides EVSEControllerInterface.service_renegotiation_supported()."""
        return False

    async def is_contactor_closed(self) -> Optional[bool]:
        """Overrides EVSEControllerInterface.is_contactor_closed()."""
        return True

    async def is_contactor_opened(self) -> bool:
        """Overrides EVSEControllerInterface.is_contactor_opened()."""
        return True

    async def get_evse_status(self) -> Optional[EVSEStatus]:
        """Overrides EVSEControllerInterface.get_evse_status()."""
        # TODO: this function can be generic to all protocols.
        #       We can make use of the method `get_evse_id`
        #       or other way to get the evse_id to request
        #       status of a specific evse_id. We can also use the
        #       `self.comm_session.protocol` obtained during SAP,
        #       and inject its value into the `get_evse_status`
        #       to decide on providing the -2ß EVSEStatus or the
        #       -2 AC or DC one and the `selected_charging_type_is_ac` in -2
        #       to decide on returning the ACEVSEStatus or the DCEVSEStatus
        #
        # Just as an example, here is how the return could look like
        # from iso15118.shared.messages.iso15118_20.common_types import (
        #    EVSENotification as EVSENotificationV20,
        # )
        # return EVSEStatus(
        #        notification_max_delay=0,
        #        evse_notification=EVSENotificationV20.TERMINATE
        #    )
        return None

    async def set_present_protocol_state(self, state: State):
        #here we may change our IEC charging mode (led colors, etc..., depending on the state of the charging session)
        logger.info(f"iso15118 state: {str(state)}")
        
        # iso15118_states = {
        #     "SupportedAppProtocol": 1,
        #     "SessionSetup": 2,
        #     "ServiceDiscovery": 3,
        #     "ServiceDetail": 4,
        #     "PaymentServiceSelection": 5,
        #     "PaymentDetails": 6,
        #     "Authorization": 7,
        #     "ChargeParameterDiscovery": 8,
        #     "PowerDelivery": 9,
        #     "ChargingStatus": 10
        # }

        # if iso15118_states[str(state)] == 1:
        #     logger.warning("Waiting 1.6 second just to test")
        #     await asyncio.sleep(1.6) #wait seconds just to test, delete later

    # ============================================================================
    # |                          AC-SPECIFIC FUNCTIONS                           |
    # ============================================================================

    async def get_ac_evse_status(self) -> ACEVSEStatus:
        """Overrides EVSEControllerInterface.get_ac_evse_status()."""
        return ACEVSEStatus(
            notification_max_delay=0,
            evse_notification=EVSENotificationV2.NONE,    # Costum notification, see later
            rcd=False,                                    # RCD, when installed associate here
        )

    async def get_ac_charge_params_v2(self) -> ACEVSEChargeParameter:
        """Overrides EVSEControllerInterface.get_ac_evse_charge_parameter()."""
        evse_nominal_voltage = PVEVSENominalVoltage(
            multiplier=0, value=self.nominalMaxVoltage, unit=UnitSymbol.VOLTAGE
        )
        evse_max_current = PVEVSEMaxCurrent(
            multiplier=0, value=self.nominalMaxCurrent, unit=UnitSymbol.AMPERE
        )
        return ACEVSEChargeParameter(
            ac_evse_status=await self.get_ac_evse_status(),
            evse_nominal_voltage=evse_nominal_voltage,
            evse_max_current=evse_max_current,
        )

    async def get_ac_charge_params_v20(
        self, energy_service: ServiceV20
    ) -> Optional[
        Union[
            ACChargeParameterDiscoveryResParams, BPTACChargeParameterDiscoveryResParams
        ]
    ]:
        """Overrides EVSEControllerInterface.get_ac_charge_params_v20()."""
        ac_charge_parameter_discovery_res_params = ACChargeParameterDiscoveryResParams(
            evse_max_charge_power=RationalNumber.get_rational_repr(self.nominalMaxPower),
            # evse_max_charge_power_l2=RationalNumber.get_rational_repr(0),
            # evse_max_charge_power_l3=RationalNumber.get_rational_repr(0),
            evse_min_charge_power=RationalNumber.get_rational_repr(1380),
            # evse_min_charge_power_l2=RationalNumber.get_rational_repr(0),
            # evse_min_charge_power_l3=RationalNumber.get_rational_repr(0),
            evse_nominal_frequency=RationalNumber.get_rational_repr(self.nominalFrequency),
            max_power_asymmetry=RationalNumber.get_rational_repr(0),
            evse_power_ramp_limit=RationalNumber.get_rational_repr(100),
            evse_present_active_power=RationalNumber.get_rational_repr(self.energyMeter.power),
            # evse_present_active_power_l2=RationalNumber.get_rational_repr(0),
            # evse_present_active_power_l3=RationalNumber.get_rational_repr(0),
        )

        if energy_service == ServiceV20.AC:
            return ac_charge_parameter_discovery_res_params
        elif energy_service == ServiceV20.AC_BPT:
            return BPTACChargeParameterDiscoveryResParams(
                **(ac_charge_parameter_discovery_res_params.dict()),
                evse_max_discharge_power=RationalNumber.get_rational_repr(self.nominalMaxPower),
                # evse_max_discharge_power_l2=RationalNumber.get_rational_repr(30000),
                # evse_max_discharge_power_l3=RationalNumber.get_rational_repr(30000),
                evse_min_discharge_power=RationalNumber.get_rational_repr(100),
                # evse_min_discharge_power_l2=RationalNumber.get_rational_repr(100),
                # evse_min_discharge_power_l3=RationalNumber.get_rational_repr(100),
            )
        else:
            raise UnknownEnergyService(f"Unknown Service {energy_service}")

    # ============================================================================
    # |                          DC-SPECIFIC FUNCTIONS                           |
    # ============================================================================

    async def get_dc_evse_status(self) -> DCEVSEStatus:
        raise NotImplementedError("get_dc_evse_status is not implemented in this class.")

    async def get_dc_charge_parameters(self) -> DCEVSEChargeParameter:
        raise NotImplementedError("get_dc_charge_parameters is not implemented in this class.")

    async def start_cable_check(self):
        """Overrides EVSEControllerInterface.start_cable_check()."""
        pass

    async def get_cable_check_status(self) -> Union[IsolationLevel, None]:
        """Overrides EVSEControllerInterface.get_cable_check_status()."""
        return IsolationLevel.VALID

    async def send_charging_command(
        self,
        ev_target_voltage: Optional[float],
        ev_target_current: Optional[float],
        is_precharge: bool = False,
        is_session_bpt: bool = False,
    ):
        pass

    async def is_evse_current_limit_achieved(self) -> bool:
        return False

    async def is_evse_voltage_limit_achieved(self) -> bool:
        return False

    async def is_evse_power_limit_achieved(self) -> bool:
        return False

    async def get_evse_max_voltage_limit(self) -> PVEVSEMaxVoltageLimit:
        return PVEVSEMaxVoltageLimit(multiplier=0, value=int(self.nominalMaxPower*1.05), unit="V")

    async def get_evse_max_current_limit(self) -> PVEVSEMaxCurrentLimit:
        present_max_current = int(self.nominalMaxPower/self.energyMeter.voltage) #use the current value read by the energy meter in terms of voltage and determine max current
        return PVEVSEMaxCurrentLimit(multiplier=0, value=present_max_current, unit="A") #=33 Amps

    async def get_evse_max_power_limit(self) -> PVEVSEMaxPowerLimit:
        return PVEVSEMaxPowerLimit(multiplier=1, value=self.nominalMaxPower, unit="W")

    async def get_dc_charge_params_v20(self, energy_service: ServiceV20) -> Union[
        DCChargeParameterDiscoveryResParams, BPTDCChargeParameterDiscoveryResParams
    ]:
        raise NotImplementedError("get_dc_charge_params_v20 is not implemented in this class.")

    @property
    async def pki_is_v20(self) -> Optional[bool]:
        """Check if the selected protocol is ISO 15118-2 or ISO 15118-20."""
        protocol = self.get_selected_protocol()

        if protocol == Protocol.ISO_15118_2:

            return False
        elif protocol == Protocol.ISO_15118_20:
            return True
        else:
            return None
        
    # FUNCTION RESPONSIBLE FOR ALL CERTIFICATE INTERACTION, SIMULATES BACKEND, SOME OF THESE WOULD USE OCPP COMMUNICATION
    async def get_15118_ev_certificate(
        self, base64_encoded_cert_installation_req: str, namespace: str
    ) -> str:
        """
        Overrides EVSEControllerInterface.get_15118_ev_certificate().

        Here we simply mock the actions of the backend.
        The code here is almost the same as what is done if USE_CPO_BACKEND
        is set to False. Except that both the request and response is base64 encoded.
        """

        self.pki_is_v20
        cert_install_req_exi = base64.b64decode(base64_encoded_cert_installation_req)
        cert_install_req = EXI().from_exi(cert_install_req_exi, namespace)
        try:
            dh_pub_key, encrypted_priv_key_bytes = encrypt_priv_key(
                oem_prov_cert=load_cert(CertPath.OEM_LEAF_DER),
                priv_key_to_encrypt=load_priv_key(
                    KeyPath.CONTRACT_LEAF_PEM,
                    KeyEncoding.PEM,
                    KeyPasswordPath.CONTRACT_LEAF_KEY_PASSWORD,
                ),
            )
        except EncryptionError:
            raise EncryptionError(
                "EncryptionError while trying to encrypt the private key for the "
                "contract certificate"
            )
        except PrivateKeyReadError as exc:
            raise PrivateKeyReadError(
                f"Can't read private key to encrypt for CertificateInstallationRes:"
                f" {exc}"
            )

        # The elements that need to be part of the signature
        contract_cert_chain = CertificateChain(
            id="id1",
            certificate=load_cert(CertPath.CONTRACT_LEAF_DER),
            sub_certificates=SubCertificates(
                certificates=[
                    load_cert(CertPath.MO_SUB_CA2_DER),
                    load_cert(CertPath.MO_SUB_CA1_DER),
                ]
            ),
        )
        encrypted_priv_key = EncryptedPrivateKey(
            id="id2", value=encrypted_priv_key_bytes
        )
        dh_public_key = DHPublicKey(id="id3", value=dh_pub_key)
        emaid = EMAID(
            id="id4", value=get_cert_cn(load_cert(CertPath.CONTRACT_LEAF_DER))
        )
        cps_certificate_chain = CertificateChain(
            certificate=load_cert(CertPath.CPS_LEAF_DER),
            sub_certificates=SubCertificates(
                certificates=[
                    load_cert(CertPath.CPS_SUB_CA2_DER),
                    load_cert(CertPath.CPS_SUB_CA1_DER),
                ]
            ),
        )

        cert_install_res = CertificateInstallationRes(
            response_code=ResponseCodeV2.OK,
            cps_cert_chain=cps_certificate_chain,
            contract_cert_chain=contract_cert_chain,
            encrypted_private_key=encrypted_priv_key,
            dh_public_key=dh_public_key,
            emaid=emaid,
        )

        try:
            # Elements to sign, containing its id and the exi encoded stream
            contract_cert_tuple = (
                cert_install_res.contract_cert_chain.id,
                EXI().to_exi(
                    cert_install_res.contract_cert_chain, Namespace.ISO_V2_MSG_DEF
                ),
            )
            encrypted_priv_key_tuple = (
                cert_install_res.encrypted_private_key.id,
                EXI().to_exi(
                    cert_install_res.encrypted_private_key, Namespace.ISO_V2_MSG_DEF
                ),
            )
            dh_public_key_tuple = (
                cert_install_res.dh_public_key.id,
                EXI().to_exi(cert_install_res.dh_public_key, Namespace.ISO_V2_MSG_DEF),
            )
            emaid_tuple = (
                cert_install_res.emaid.id,
                EXI().to_exi(cert_install_res.emaid, Namespace.ISO_V2_MSG_DEF),
            )

            elements_to_sign = [
                contract_cert_tuple,
                encrypted_priv_key_tuple,
                dh_public_key_tuple,
                emaid_tuple,
            ]
            # The private key to be used for the signature
            signature_key = load_priv_key(
                KeyPath.CPS_LEAF_PEM,
                KeyEncoding.PEM,
                KeyPasswordPath.CPS_LEAF_KEY_PASSWORD,
            )

            signature = create_signature(elements_to_sign, signature_key)

        except PrivateKeyReadError as exc:
            raise Exception(
                "Can't read private key needed to create signature "
                f"for CertificateInstallationRes: {exc}",
            )
        except Exception as exc:
            raise Exception(f"Error creating signature {exc}")

        if isinstance(cert_install_req, CertificateInstallationReq):
            header = MessageHeaderV2(
                session_id=cert_install_req.header.session_id,
                signature=signature,
            )
            body = Body.parse_obj(
                {"CertificateInstallationRes": cert_install_res.dict()}
            )
            to_be_exi_encoded = V2GMessageV2(header=header, body=body)
            exi_encoded_cert_installation_res = EXI().to_exi(
                to_be_exi_encoded, Namespace.ISO_V2_MSG_DEF
            )

            # base64.b64encode in Python is a binary transform
            # so the return value is byte[]
            # But the CPO expects exi_encoded_cert_installation_res
            # as a string, hence the added .decode("utf-8")
            base64_encode_cert_install_res = base64.b64encode(
                exi_encoded_cert_installation_res
            ).decode("utf-8")

            return base64_encode_cert_install_res
        else:
            logger.info(f"Ignoring EXI decoding of a {type(cert_install_req)} message.")
            return ""

    async def update_data_link(self, action: SessionStopAction) -> None:
        """
        Overrides EVSEControllerInterface.update_data_link().
        """
        logger.info(f"Updating data link: {action}")
        pass

    def ready_to_charge(self) -> bool: 
        """
        Overrides EVSEControllerInterface.ready_to_charge().      
        """
        ready_charge = True
        logger.info(f"Ready to Charge: {ready_charge}")
        self.basicCharging.charge_mode = 0 #authenticated and allowed to charge
        return ready_charge

    async def session_ended(self, current_state: str, reason: str):
        """
        Reports the state and reason where the session ended.

        @param current_state: The current SDP/SAP/DIN/ISO15118-2/ISO15118-20 state.
        @param reason: Reason for ending the session.
        @param last_message: The last message that was either sent/received.
        """
        logger.info(f"Session ended in {current_state} ({reason}).")

    async def send_display_params(self):
        """
        Share display params with CS.
        """
        logger.info("Send display params to CS.")

    async def send_rated_limits(self):
        """
        Overrides EVSEControllerInterface.send_rated_limits
        """
        logger.info("Send rated limits to CS.")




# Describes Our Station parameters and limits
############################################################### get_evse_context / ver melhor isto depois, para substituir pelas nossas variaveis mesmo
def get_evse_context():
    ac_limits = EVSEACCPDLimits(
        max_current=10,
        max_charge_power=10,
        min_charge_power=10,
        max_charge_power_l2=10,
        max_charge_power_l3=10,
        min_charge_power_l2=10,
        min_charge_power_l3=10,
        max_discharge_power=10,
        min_discharge_power=10,
        max_discharge_power_l2=10,
        max_discharge_power_l3=10,
        min_discharge_power_l2=10,
        min_discharge_power_l3=10,
    )
    dc_limits = EVSEDCCPDLimits(
        max_charge_power=10,
        min_charge_power=10,
        max_charge_current=10,
        min_charge_current=10,
        max_voltage=10,
        min_voltage=10,
        # 15118-20 DC BPT
        max_discharge_power=10,
        min_discharge_power=10,
        max_discharge_current=10,
        min_discharge_current=10,
    )
    ac_cl_limits = EVSEACCLLimits(
        max_charge_power=10,
        max_charge_power_l2=10,
        max_charge_power_l3=10,
        max_charge_reactive_power=10,
        max_charge_reactive_power_l2=10,
        max_charge_reactive_power_l3=10,
        # BPT attributes
        max_discharge_power=10,
        max_discharge_power_l2=10,
        max_discharge_power_l3=10,
        max_discharge_reactive_power=10,
        max_discharge_reactive_power_l2=10,
        max_discharge_reactive_power_l3=10,
    )
    dc_cl_limits = EVSEDCCLLimits(
        # Optional in 15118-20 DC CL (Scheduled)
        max_charge_power=10,
        min_charge_power=10,
        max_charge_current=10,
        max_voltage=10,
        # Optional and present in 15118-20 DC BPT CL (Scheduled)
        max_discharge_power=10,
        min_discharge_power=10,
        max_discharge_current=10,
        min_voltage=10,
    )
    rated_limits: EVSERatedLimits = EVSERatedLimits(
        ac_limits=ac_limits,
        dc_limits=dc_limits,
    )

    session_limits: EVSESessionLimits = EVSESessionLimits(
        ac_limits=ac_cl_limits,
        dc_limits=dc_cl_limits,
    )
    evse_data_context = EVSEDataContext(
        rated_limits=rated_limits, session_limits=session_limits
    )
    evse_data_context.nominal_voltage = 10
    evse_data_context.nominal_frequency = 10
    evse_data_context.max_power_asymmetry = 10
    evse_data_context.power_ramp_limit = 10
    evse_data_context.present_active_power = 10
    evse_data_context.present_active_power_l2 = 10
    evse_data_context.present_active_power_l3 = 10
    evse_data_context.current_regulation_tolerance = 10
    evse_data_context.energy_to_be_delivered = 10
    evse_data_context.present_current = 1
    evse_data_context.present_voltage = 1
    return evse_data_context