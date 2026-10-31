# Kaaval pump-station tag / register map

The plant is a water pumping station with a discharge-pressure safety interlock.
The PLC serves these tags from **S7comm DB1** (big-endian, 32 bytes). The gateway
polls DB1 over S7comm and mirrors every tag onto an **OPC UA** server. This map
is the contract between `sim/plc.py`, `sim/gateway.py`, and every consumer; it is
generated to match `sim/tags.py` (the single source of truth).

## Access semantics
- **RO** — physics output. The PLC physics loop writes it; clients read it.
- **RW** — control input. Clients write it (gateway/HMI, and — anomalously — the
  Phase-3 attacker over direct S7comm); the physics loop only reads it.

RW and RO booleans live in **separate bytes** so a client writing the RW byte
cannot clobber RO status bits, and vice-versa.

## S7comm DB1 register map (big-endian)

| S7 address | Type | Tag | Access | Unit | Baseline |
|---|---|---|---|---|---|
| DB1.DBD0  | REAL | discharge_pressure_bar  | RO | bar  | ~5.0 |
| DB1.DBD4  | REAL | flow_rate_m3h           | RO | m³/h | ~125 |
| DB1.DBD8  | REAL | pump_speed_pct          | RO | %    | 50 |
| DB1.DBD12 | REAL | tank_level_pct          | RO | %    | ~70 |
| DB1.DBD16 | REAL | pump_setpoint_pct       | RW | %    | 50 |
| DB1.DBD20 | REAL | pressure_high_limit_bar | RW | bar  | 8.0 |
| DB1.DBX24.0 | BOOL | interlock_enabled     | RW | bool | true |
| DB1.DBX25.0 | BOOL | interlock_tripped     | RO | bool | false |
| DB1.DBX25.1 | BOOL | pump_running          | RO | bool | true |

DB1 size = 32 bytes. Byte 24 = RW boolean byte; byte 25 = RO boolean byte.

## OPC UA node map

- Endpoint: `opc.tcp://<gateway>:4840/kaaval/`
- Namespace URI: `http://traboda.com/kaaval/pumpstation` (index typically `ns=2`)
- Object: `PumpStation`
- One variable per tag, string NodeId `ns=2;s=PumpStation.<Name>`:

| OPC UA NodeId | Tag | Type | Access |
|---|---|---|---|
| `ns=2;s=PumpStation.DischargePressure`  | discharge_pressure_bar  | Float   | RO |
| `ns=2;s=PumpStation.FlowRate`           | flow_rate_m3h           | Float   | RO |
| `ns=2;s=PumpStation.PumpSpeed`          | pump_speed_pct          | Float   | RO |
| `ns=2;s=PumpStation.TankLevel`          | tank_level_pct          | Float   | RO |
| `ns=2;s=PumpStation.PumpSetpoint`       | pump_setpoint_pct       | Float   | RW |
| `ns=2;s=PumpStation.PressureHighLimit`  | pressure_high_limit_bar | Float   | RW |
| `ns=2;s=PumpStation.InterlockEnabled`   | interlock_enabled       | Boolean | RW |
| `ns=2;s=PumpStation.InterlockTripped`   | interlock_tripped       | Boolean | RO |
| `ns=2;s=PumpStation.PumpRunning`        | pump_running            | Boolean | RO |

## Operating envelope (physics)
- Baseline pressure band: **4.0–6.0 bar** (nominal 5.0 at 50 % setpoint).
- High-pressure interlock limit: **8.0 bar** → trips the pump when armed.
- Burst threshold (UI): **12.0 bar**.
- Pressure curve: `target = 1.0 + 3·s + 10·s²` bar, where `s = speed/100`
  (50 % → 5.0 bar, 100 % → 14.0 bar). First-order lag, τ_speed=2 s, τ_press=3 s.

## Attack vs. defense (later phases)
- **Attack:** disable `interlock_enabled` and force `pump_setpoint_pct=100` over
  **direct S7comm to the PLC** (bypassing the gateway) → pressure climbs past the
  limit unchecked toward burst.
- **Recovery:** re-arm `interlock_enabled` and restore `pump_setpoint_pct` through
  the **gateway over OPC UA** (the legitimate path) → pressure returns to band.
