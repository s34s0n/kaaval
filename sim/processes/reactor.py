# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Process #2 — jacketed continuous stirred-tank reactor (CSTR).

A genuinely different plant from the pump: different physics (exothermic reaction
heat vs. jacket cooling), different S7 register layout, and a different OPC node
set (``Reactor.*``). It is structurally analogous to the pump so the SAME response
playbook shape applies — a high-temperature safety interlock that trips the feed,
and a coolant-valve control setpoint:

  * Baseline: coolant valve 50 %, feed running, interlock armed -> ~80 °C
    (band 60–120 °C), pressure ~2.2 bar.
  * Attack: disable the high-temp interlock AND cut the coolant valve to 0 % over
    direct S7comm -> exothermic self-heating runs away toward DANGER (~280 °C):
    a thermal-runaway / loss-of-containment condition (the reactor analog of the
    pump's pipe burst).
  * Recovery: re-arm the interlock (trips the feed, stopping reaction heat) and
    restore the coolant setpoint -> temperature falls back into band.

The physics is a lumped energy balance: dT/dt = q_rxn - q_cool - q_ambient, where
q_rxn carries a positive temperature feedback (autocatalytic) so removing cooling
produces a real runaway rather than a linear ramp.
"""

from __future__ import annotations

import random

from tagspec import Tag

# --- identity ----------------------------------------------------------------
NAME = "reactor"
NAMESPACE_URI = "http://traboda.com/kaaval/reactor"
OBJECT_NAME = "Reactor"

# --- S7 DB layout ------------------------------------------------------------
DB_NUMBER = 1
DB_SIZE = 32

RW_BOOL_BYTE = 24
BIT_INTERLOCK_ENABLED = 0
RO_BOOL_BYTE = 25
BIT_TRIPPED = 0
BIT_FEED_RUNNING = 1

TAGS: list[Tag] = [
    Tag("reactor_temp_c",        "REAL", 0,  None, "RO", "degC", "Reactor.ReactorTemp"),
    Tag("reactor_pressure_bar",  "REAL", 4,  None, "RO", "bar",  "Reactor.ReactorPressure"),
    Tag("coolant_flow_pct",      "REAL", 8,  None, "RO", "%",    "Reactor.CoolantFlow"),
    Tag("agitator_speed_pct",    "REAL", 12, None, "RO", "%",    "Reactor.AgitatorSpeed"),
    Tag("coolant_valve_pct",     "REAL", 16, None, "RW", "%",    "Reactor.CoolantValve"),
    Tag("temp_high_limit_c",     "REAL", 20, None, "RW", "degC", "Reactor.TempHighLimit"),
    Tag("hightemp_interlock_enabled", "BOOL", RW_BOOL_BYTE, BIT_INTERLOCK_ENABLED, "RW", "bool", "Reactor.HighTempInterlockEnabled"),
    Tag("hightemp_tripped",      "BOOL", RO_BOOL_BYTE, BIT_TRIPPED,       "RO", "bool", "Reactor.HighTempTripped"),
    Tag("feed_pump_running",     "BOOL", RO_BOOL_BYTE, BIT_FEED_RUNNING,  "RO", "bool", "Reactor.FeedPumpRunning"),
]

# Safety descriptor — what the attacker manipulates to drive the process unsafe,
# and the variable + band the backend uses for "in band" / status.
SAFETY = {
    "variable": "reactor_temp_c",
    "band": (60.0, 120.0),
    "danger": 280.0,
    "interlock_tag": "hightemp_interlock_enabled",
    "danger_control_tag": "coolant_valve_pct",
    "danger_control_value": 0.0,          # attacker cuts coolant to 0 %
    "restore_control_value": 50.0,        # recovery coolant setpoint
}

# --- physics tuning (per-second rates; scaled by dt in tick) -----------------
T_COOLANT = 20.0       # degC, jacket coolant supply temperature
T_REF = 80.0           # degC, baseline operating temperature
HEAT_IN = 6.6          # degC/s, base exothermic reaction heat (feed running)
SELF_HEAT = 0.10       # /s, autocatalytic feedback gain above T_REF (runaway driver)
COOL_K = 0.20          # /s per coolant-fraction, jacket heat-removal coefficient
AMB = 0.01             # /s, ambient loss
TAU_COOL = 3.0         # s, coolant flow first-order lag behind the valve
# Wide reset margin: once the high-temp interlock trips the feed, keep it off until
# the reactor has cooled well back into band (so recovery is a clean fast cooldown,
# not a slow crawl with the feed cycling back on at the band edge).
TRIP_HYSTERESIS = 45.0 # degC below the limit before a tripped interlock resets
TEMP_NOISE = 0.15      # degC measurement jitter
DANGER_CLAMP = 320.0   # degC hard clamp (sensor saturates)

BASELINE_VALVE = 50.0
BASELINE_HIGH_LIMIT = 150.0
BASELINE_AGITATOR = 70.0


def initial_state() -> dict:
    """Clean pre-attack baseline (~80 degC, in band, interlock armed)."""
    return {
        "reactor_temp_c": T_REF,
        "reactor_pressure_bar": _pressure(T_REF),
        "coolant_flow_pct": BASELINE_VALVE,
        "agitator_speed_pct": BASELINE_AGITATOR,
        # RW control inputs
        "coolant_valve_pct": BASELINE_VALVE,
        "temp_high_limit_c": BASELINE_HIGH_LIMIT,
        "hightemp_interlock_enabled": True,
        # RO status
        "hightemp_tripped": False,
        "feed_pump_running": True,
    }


def tick(state: dict, dt: float) -> dict:
    """Advance the process by ``dt`` seconds. Returns the same dict, mutated.

    Reads control inputs (coolant valve, high-temp limit, interlock) and updates
    outputs; never writes the control inputs themselves.
    """
    valve = _clamp(state["coolant_valve_pct"], 0.0, 100.0)
    limit = state["temp_high_limit_c"]
    interlock = bool(state["hightemp_interlock_enabled"])
    T = state["reactor_temp_c"]
    tripped = bool(state["hightemp_tripped"])
    coolant_flow = state["coolant_flow_pct"]

    # --- safety interlock ----------------------------------------------------
    # Armed interlock trips the feed when temperature reaches the limit, halting
    # reaction heat. A disabled interlock lets the exotherm run away.
    if interlock and T >= limit:
        tripped = True
    elif tripped and T < (limit - TRIP_HYSTERESIS):
        tripped = False
    feed_running = not tripped

    # --- coolant flow follows the valve (first-order) ------------------------
    coolant_flow += (valve - coolant_flow) * min(1.0, dt / TAU_COOL)
    coolant_flow = _clamp(coolant_flow, 0.0, 100.0)
    cf = coolant_flow / 100.0

    # --- lumped energy balance ----------------------------------------------
    q_rxn = (HEAT_IN + SELF_HEAT * max(0.0, T - T_REF)) if feed_running else 0.0
    q_cool = COOL_K * cf * (T - T_COOLANT)
    q_amb = AMB * (T - T_COOLANT)
    T += (q_rxn - q_cool - q_amb) * dt
    T = _clamp(T, T_COOLANT, DANGER_CLAMP)

    agitator = _clamp(BASELINE_AGITATOR + random.uniform(-1.0, 1.0), 0.0, 100.0)

    state["reactor_temp_c"] = T + random.uniform(-TEMP_NOISE, TEMP_NOISE)
    state["reactor_pressure_bar"] = _pressure(T)
    state["coolant_flow_pct"] = coolant_flow
    state["agitator_speed_pct"] = agitator
    state["hightemp_tripped"] = tripped
    state["feed_pump_running"] = feed_running
    return state


def _pressure(temp_c: float) -> float:
    """Cosmetic vessel pressure that tracks temperature (vapor pressure proxy)."""
    return 1.0 + 0.02 * (temp_c - T_COOLANT)


def _clamp(v: float, lo: float, hi: float) -> float:
    return lo if v < lo else hi if v > hi else v
