import os
import asyncio

from evse.iec61851.basic_charging.build_basic_charging import BasicChargingStruct
#=======================================LOGS=================================#
import logging
logger = logging.getLogger(__name__)
#============================PYSLAC===========================#
from pyslac.session import SlacEvseSession, SlacSessionController

from pyslac.enums import (
    C_SEQU_RETRY_TIMES,
    CM_ATTEN_CHAR,
    CM_ATTEN_PROFILE,
    CM_MNBC_SOUND,
    CM_SET_KEY,
    CM_SLAC_MATCH,
    CM_SLAC_PARM,
    CM_START_ATTEN_CHAR,
    ETH_TYPE_HPAV,
    EVSE_PLC_MAC,
    HOMEPLUG_MMV,
    MMTYPE_CNF,
    MMTYPE_IND,
    MMTYPE_REQ,
    MMTYPE_RSP,
    SLAC_ATTEN_TIMEOUT,
    SLAC_GROUPS,
    SLAC_LIMIT,
    SLAC_MSOUNDS,
    SLAC_PAUSE,
    SLAC_RESP_TYPE,
    STATE_MATCHED,
    STATE_MATCHING,
    STATE_UNMATCHED,
    COMMUNICATION_HLC,
    COMMUNICATION_LLC,
    COMMUNICATION_UNDEFINED,
    COMMUNICATION_DETERMINING,
    FramesSizes,
    Timers,
)

class Slac_Handler(SlacSessionController):
    slac_running_session: SlacEvseSession #slac evse session class
    level_communication: int #-1 for not defined yet, 0 for llc, 1 for hlc
    slac_attempt: int #current number of attempts at slac in this session, 1 attempt + 2 retry max

    def __init__(self, evse_id):
        super().__init__() #calls parent's classes initialization
        self.level_communication = COMMUNICATION_UNDEFINED #Communication Level starts undefined
        self.max_slac_retries = int(os.getenv("MAX_SLAC_RETRY_TIMES", str(C_SEQU_RETRY_TIMES)))
        self.max_slac_attempts = 1 + self.max_slac_retries # 1 initial attempt + retries
        self.evse_id = evse_id

        hlc_network_interface: str = os.getenv("NETWORK_INTERFACE")
        try:
            self.slac_running_session = SlacEvseSession(self.evse_id, hlc_network_interface)
        except (OSError, TimeoutError, ValueError) as e:
            logger.error(f"PLC chip initialization failed for interface {hlc_network_interface} \n")
            raise(e)        
    
    async def handling(self, cp_controller: BasicChargingStruct): #maybe enters session_handling_hlc
        logger.debug("Starting slac handling...")
        try:
            while self.level_communication not in (COMMUNICATION_HLC, COMMUNICATION_LLC):
                if self.level_communication == COMMUNICATION_UNDEFINED:
                    self.level_communication = COMMUNICATION_DETERMINING

                if self.slac_running_session.state != STATE_MATCHED: # not matched and HLC not tried yet

                    if not cp_controller.hlc_charging:
                        logger.debug("PLACING PWM INTO 5% DutyCycle")
                        cp_controller.hlc_charging = 1 # enable hlc charging in basiccharging module, 5% pwm
                        await self.slac_running_session.evse_set_key() #set SLAC key, it wasnt set yet

                    elif cp_controller.hlc_charging: # if hlc_charging enabled in basic charging
                        for slac_attempt in range(0, self.max_slac_attempts):  #allow 5% dutycycle for HLC communication, when in state B, C or D || 1st atempt + 3 retries=4atempts
                            logger.debug(f"SLAC Attempt number {slac_attempt}")
                            await self.process_cp_state(self.slac_running_session, cp_controller.committed_state) # try slac matching

                            if self.slac_running_session.state == STATE_MATCHED:
                                self.level_communication = COMMUNICATION_HLC
                                break
                            
                            elif self.slac_running_session.state == STATE_UNMATCHED: #if SLAC failed, go to F state for SLAC_E_F_TIMEOUT time
                                logger.debug("SLAC entering T_STEP_EF")
                                cp_controller.force_F = 1 #force state F
                                await asyncio.sleep(Timers.SLAC_E_F_TIMEOUT)

                                if slac_attempt == self.max_slac_retries: # if this is the last retry, disable hlc charging and resume LLC communication
                                    logger.debug("PEV-EVSE MATCHED Failed: No more retries possible; Resuming LLC Charging")
                                    cp_controller.hlc_charging = 0 # disable hlc charging
                                    self.level_communication = COMMUNICATION_LLC # force llc communication, will atempt basic charging (using LLC)
                                    
                                cp_controller.force_F = 0 #leave state F
                                while cp_controller.committed_state == "F": # Make sure cp leaves state F before proceeding with the slac handling
                                    await asyncio.sleep(0.1)
                                logger.debug("SLAC exited T_STEP_EF")

                            else:
                                raise Exception(
                                        f"UNDEFINED SLAC HANDLING BEHAVIOUR."
                                        f"Committed State: {cp_controller.committed_state}, "
                                        f"Charge Mode: {cp_controller.charge_mode}",
                                        f"HLC charging: {cp_controller.hlc_charging}",
                                        f"Session State: {self.slac_running_session.state}"
                                    )   
                asyncio.sleep(0.1) # loop sleep
        except Exception as e:
            logger.error(e)

"""
NOTAS

            In case a communication has already been established within 5 % control pilot duty
cycle (“Matched state” reached or matching process ongoing), a change from 5 %
to a nominal duty cycle shall be done with a X1 state in the middle (minimum time
as defined in [IEC-3] Seq 9.2), to signal the EV that the control pilot duty cycle will
change to a nominal duty cycle.

            If an AC EVSE applies a 5 % control pilot duty cycle, and the EVSE receives no SLAC
request within TT_EVSE_SLAC_init, the EVSE shall go to state E or F for T_step_EF,
shall go back to 5 % duty cycle, and shall reset the TT_EVSE_SLAC_init timeout
before being ready to answer a matching request again. This sequence shall be
retried C_sequ_retry times. At the end, without any reaction, the EVSE shall go to
state X1. -> PAGE 9 ISO-3

In case basic charging is used as back-up of HLC-C (e.g. when HLC-C has failed), the duty cycle is allowed
to change due to dynamically changed grid information, according [IEC-1] requirements
"""