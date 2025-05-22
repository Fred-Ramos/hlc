import os
import asyncio

from evse.iec61851.basic_charging.build_basic_charging import BasicChargingStruct
#=======================================LOGS=================================#
import logging
logger = logging.getLogger(__name__)
#============================PYSLAC===========================#
from pyslac.session import SlacEvseSession, SlacSessionController

from pyslac.enums import (
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
    HLC_SUCESS,
    LLC_COM,
    HLC_NO_LINK,
    FramesSizes,
    Timers,
)

C_SEQU_RETRY_TIMES = 3

class SlacHandler(SlacSessionController):
    slac_running_session: SlacEvseSession #slac evse session class
    level_communication: int #-1 for not defined yet, 0 for llc, 1 for hlc
    slac_attempt: int #current number of attempts at slac in this session, 1 attempt + 2 retry max

    def __init__(self, evse_id):
        super().__init__() #calls parent's classes initialization
        self.level_communication = -1 #Communication Level starts undefined
        self.slac_attempt = 0 #no attempt yet
        self.evse_id = evse_id

        hlc_network_interface: str = os.getenv("NETWORK_INTERFACE")
        try:
            self.slac_running_session = SlacEvseSession(self.evse_id, hlc_network_interface)
        except (OSError, TimeoutError, ValueError) as e:
            logger.error(f"PLC chip initialization failed for interface {hlc_network_interface} \n")
            return        

    async def handling(self, cp_controller: BasicChargingStruct): #maybe enters session_handling_hlc
        try:
            if self.slac_running_session.state == STATE_UNMATCHED: #not matched and HLC not tried yet
                if cp_controller.hlc_charging != HLC_SUCESS:
                    logger.debug("PLACING PWM INTO 5% DutyCycle")
                    cp_controller.hlc_charging = 1 #goes to state B2
                    asyncio.sleep(0.1) #wait to make sure routine triggers
                    await self.slac_running_session.evse_set_key() #set SLAC key, it wasnt set yet
                    return
                elif cp_controller.hlc_charging == 1 and self.slac_attempt < C_SEQU_RETRY_TIMES+1: #allow 5% dutycycle for HLC communication, when in state B, C or D || 1st atempt + 3 retries=4atempts
                    logger.debug("PWM already 5% DutyCycle")
                    #implement slac message
                    self.slac_attempt+=1
                    logger.debug(f"SLAC Attempt number {self.slac_attempt}")
                    self.level_communication = await self.process_cp_state(self.slac_running_session, cp_controller.committed_state)
                    if self.level_communication == HLC_NO_LINK: #if HLC failed, go to E state for SLAC_E_F_TIMEOUT time
                        logger.debug("CHANGING TO -12 V")
                        cp_controller.force_F = 1 #force state F
                        await asyncio.sleep(Timers.SLAC_E_F_TIMEOUT)
                        logger.debug("CHANGING BACK TO 12 V")
                        cp_controller.force_F = 0 #leave state F
                elif cp_controller.hlc_charging == 1 and self.slac_attempt > C_SEQU_RETRY_TIMES:
                    logger.debug("PEV-EVSE MATCHED Failed: No more retries " "possible")
                    self.level_communication = LLC_COM #Will atempt basic charging (using LLC)
                else:
                    raise Exception(
                        f"UNDEFINED SLAC HANDLING BEHAVIOUR."
                        f"Committed State: {cp_controller.committed_state}, "
                        f"Charge Mode: {cp_controller.charge_mode}",
                        f"HLC charging: {cp_controller.hlc_charging}"
                    )
            else:
                raise Exception("Slac Handling running while state not unmatched")

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