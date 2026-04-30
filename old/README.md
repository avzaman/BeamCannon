# BeamCannon

Wi-Fi beamforming feedback injection tool.  
Inspired by BeamCraft (ACM MobiCom'24).

Supports 802.11ac (VHT) and 802.11ax (HE/Wi-Fi 6) explicit beamforming feedback forgery.

## Attack Modes

**Pillage** — Forge victim BFI to be orthogonal to the genuine channel direction,
misdirecting the AP's beam and reducing victim throughput by ~80%.

**Plunder** — Forge victim BFI to be orthogonal to the quartermaster's channel
direction, eliminating inter-user interference at the quartermaster and boosting
their throughput at the victim's expense.

## Requirements

### Hardware
- Monitor mode NIC with confirmed packet injection support
  (tested: Alfa AWUS036ACM / MT7612U, Realtek RTL8821AE / rtw88)
- Target AP with explicit 802.11ac or 802.11ax beamforming
- Victim device actively downloading (iperf3 recommended)

### Software
- Linux, kernel 6.2+
- libpcap >= 1.10
- Eigen3 >= 3.3
- g++ with C++17 support

## Build

```bash
sudo apt install -y build-essential libpcap-dev libeigen3-dev
make
```

## Usage

```bash
# Put NIC in monitor mode first
sudo airmon-ng check kill
sudo airmon-ng start wlan0

# Run BeamCannon
sudo ./beamcannon --iface wlan0mon
sudo ./beamcannon --iface wlan0mon --log my_session.log
```

## Workflow

1. BeamCannon scans 5GHz channels and lists visible APs (Fleet)
2. Select your target AP
3. BeamCannon auto-locks to the AP's channel and bandwidth
4. Client scan lists all beamforming clients (Crew)
5. Select Pillage or Plunder
6. Select Mark(s) (victims) and optionally Quartermaster (beneficiary)
7. BeamCannon auto-detects Nr/Nc/Nst from a live BFI frame
8. Attack runs with live timing metrics

## Metrics

The live display shows per-victim compute+inject time averaged over the
last 20 broadsides (VOLLEY_WINDOW), compared against the detected sounding
interval:

- GREEN  [CLEAR]   — < 40% of sounding interval
- YELLOW [CAUTION] — 40-70% of sounding interval
- RED    [DANGER]  — > 70% of sounding interval

All events are logged to the session log file for offline analysis.

## Log Format

```
2025-04-27 14:32:01.123 [START]   iface=wlan0mon ap=aa:bb:cc:dd:ee:ff ...
2025-04-27 14:32:01.456 [MODE]    pillage victims=aa:bb:cc:11:22:33
2025-04-27 14:32:01.789 [INJECT]  victim=aa:bb:cc:11:22:33 compute_ms=1.840 result=ok seq=0
2025-04-27 14:34:14.001 [SUMMARY] total=247 success=245 failed=2 ...
```

## Disclaimer

This tool is for authorized security research only.
Only use against equipment you own or have explicit written permission to test.
