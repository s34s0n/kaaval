# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Process #1 — water pumping station (Siemens-controlled).

The original Kaaval plant, extracted unchanged into the pluggable-process layout.
At the baseline 50 % setpoint the discharge pressure settles near 5.0 bar
(band 4.0–6.0) with the safety interlock armed; driving the setpoint to 100 % with
the interlock *disabled* pushes pressure toward BURST_BAR — the attack impact.
"""

from __future__ import annotations

import random

from tagspec import Tag

# --- identity ----------------------------------------------------------------
NAME = "pump"
NAMESPACE_URI = "http://traboda.com/kaaval/pumpstation"
OBJECT_NAME = "PumpStation"

# --- S7 DB layout ------------------------------------------------------------
DB_NUMBER = 1
DB_SIZE = 32  # bytes (rounded up from the highest offset in use)

# Booleans split across two bytes so RW and RO bits never share a byte.
RW_BOOL_BYTE = 24            # control-input bits (written by clients)
BIT_INTERLOCK_ENABLED = 0
RO_BOOL_BYTE = 25            # status bits (written by the physics loop)
BIT_INTERLOCK_TRIPPED = 0
BIT_PUMP_RUNNING = 1

# Order here defines the documented register map (see docs/TAGMAP.md).
TAGS: list[Tag] = [
    Tag("discharge_pressure_bar",  "REAL", 0,  None, "RO", "bar",  "PumpStation.DischargePressure"),
    Tag("flow_rate_m3h",           "REAL", 4,  None, "RO", "m3/h", "PumpStation.FlowRate"),
    Tag("pump_speed_pct",          "REAL", 8,  None, "RO", "%",    "PumpStation.PumpSpeed"),
    Tag("tank_level_pct",          "REAL", 12, None, "RO", "%",    "PumpStation.TankLevel"),
    Tag("pump_setpoint_pct",       "REAL", 16, None, "RW", "%",    "PumpStation.PumpSetpoint"),
    Tag("pressure_high_limit_bar", "REAL", 20, None, "RW", "bar",  "PumpStation.PressureHighLimit"),
    Tag("interlock_enabled", "BOOL", RW_BOOL_BYTE, BIT_INTERLOCK_ENABLED, "RW", "bool", "PumpStation.InterlockEnabled"),
    Tag("interlock_tripped", "BOOL", RO_BOOL_BYTE, BIT_INTERLOCK_TRIPPED, "RO", "bool", "PumpStation.InterlockTripped"),
    Tag("pump_running",      "BOOL", RO_BOOL_BYTE, BIT_PUMP_RUNNING,      "RO", "bool", "PumpStation.PumpRunning"),
]

# Safety descriptor — consumed by the attacker (what to manipulate to drive the
# process unsafe) and by the backend (the variable + band that define "in band").
SAFETY = {
    "variable": "discharge_pressure_bar",
    "band": (4.0, 6.0),
    "danger": 12.0,                       # BURST_BAR
    "interlock_tag": "interlock_enabled",
    "danger_control_tag": "pump_setpoint_pct",
    "danger_control_value": 100.0,        # attacker pushes setpoint here
    "restore_control_value": 50.0,        # recovery setpoint
}

# --- physics tuning ----------------------------------------------------------
P_BASE = 1.0          # bar, residual/static pressure with the pump idle
TAU_SPEED = 2.0       # s, pump speed first-order time constant
TAU_PRESS = 3.0       # s, discharge pressure first-order time constant
FLOW_MAX = 250.0      # m3/h at 100 % speed
PRESSURE_NOISE = 0.03 # bar, +/- measurement jitter
TRIP_HYSTERESIS = 1.0 # bar below the limit before a tripped interlock auto-resets

_P_A = 3.0
_P_B = 10.0

BASELINE_SETPOINT = 50.0
BASELINE_HIGH_LIMIT = 8.0
BASELINE_TANK_LEVEL = 70.0


def target_pressure(speed_pct: float) -> float:
    s = max(0.0, speed_pct) / 100.0
    return P_BASE + _P_A * s + _P_B * s * s


def initial_state() -> dict:
    """Clean pre-attack baseline."""
    return {
        "discharge_pressure_bar": 5.0,
        "flow_rate_m3h": FLOW_MAX * BASELINE_SETPOINT / 100.0,
        "pump_speed_pct": BASELINE_SETPOINT,
        "tank_level_pct": BASELINE_TANK_LEVEL,
        # RW control inputs
        "pump_setpoint_pct": BASELINE_SETPOINT,
        "pressure_high_limit_bar": BASELINE_HIGH_LIMIT,
        "interlock_enabled": True,
        # RO status
        "interlock_tripped": False,
        "pump_running": True,
    }


def tick(state: dict, dt: float) -> dict:
    """Advance the process by ``dt`` seconds. Returns the same dict, mutated."""
    setpoint = _clamp(state["pump_setpoint_pct"], 0.0, 100.0)
    high_limit = state["pressure_high_limit_bar"]
    interlock_enabled = bool(state["interlock_enabled"])
    pressure = state["discharge_pressure_bar"]
    speed = state["pump_speed_pct"]
    tripped = bool(state["interlock_tripped"])

    if interlock_enabled and pressure >= high_limit:
        tripped = True
    elif tripped and pressure < (high_limit - TRIP_HYSTERESIS):
        tripped = False

    pump_running = not tripped
    commanded_speed = 0.0 if tripped else setpoint

    speed += (commanded_speed - speed) * min(1.0, dt / TAU_SPEED)
    speed = _clamp(speed, 0.0, 100.0)

    tgt = target_pressure(speed)
    pressure += (tgt - pressure) * min(1.0, dt / TAU_PRESS)
    pressure = max(P_BASE, pressure)

    flow = FLOW_MAX * speed / 100.0
    level = _clamp(state["tank_level_pct"] + random.uniform(-0.05, 0.05), 60.0, 80.0)

    state["pump_speed_pct"] = speed
    state["discharge_pressure_bar"] = pressure + random.uniform(-PRESSURE_NOISE, PRESSURE_NOISE)
    state["flow_rate_m3h"] = flow
    state["tank_level_pct"] = level
    state["interlock_tripped"] = tripped
    state["pump_running"] = pump_running
    return state


def _clamp(v: float, lo: float, hi: float) -> float:
    return lo if v < lo else hi if v > hi else v
