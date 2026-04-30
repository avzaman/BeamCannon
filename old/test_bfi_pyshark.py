#!/usr/bin/env python3
"""
BeamCannon - BFI frame detector using Pyshark
No display filter - catches everything and filters in Python
"""
import pyshark
import sys
import time
import signal

IFACE = sys.argv[1] if len(sys.argv) > 1 else 'wlan0'
DURATION = int(sys.argv[2]) if len(sys.argv) > 2 else 120

packet_count = 0
mgmt_count = 0
action_count = 0
bfi_count = 0
start_time = time.time()

def signal_handler(sig, frame):
    elapsed = time.time() - start_time
    print(f'\n--- Results after {elapsed:.1f}s ---')
    print(f'Total packets  : {packet_count}')
    print(f'Mgmt frames    : {mgmt_count}')
    print(f'Action frames  : {action_count}')
    print(f'BFI frames     : {bfi_count}')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

print(f'[*] BFI detector - interface: {IFACE}')
print(f'[*] Duration: {DURATION}s  (Ctrl+C to stop)')
print(f'[*] No display filter - raw capture\n')

# No display_filter - capture everything
capture = pyshark.LiveCapture(interface=IFACE)

t_end = time.time() + DURATION

for pkt in capture.sniff_continuously():
    if time.time() > t_end:
        break

    packet_count += 1

    # Progress every 200 packets
    if packet_count % 200 == 0:
        elapsed = time.time() - start_time
        print(f'  [{elapsed:.0f}s] pkts={packet_count} mgmt={mgmt_count} '
              f'action={action_count} bfi={bfi_count}')

    try:
        # Check for wlan layer
        if not hasattr(pkt, 'wlan'):
            continue

        wlan = pkt.wlan

        # Get frame type and subtype
        fc_type = None
        fc_subtype = None
        if hasattr(wlan, 'fc_type'):
            fc_type = int(wlan.fc_type)
        if hasattr(wlan, 'fc_type_subtype'):
            try:
                fc_subtype = int(wlan.fc_type_subtype, 16)
            except:
                fc_subtype = int(wlan.fc_type_subtype)

        # Management frames: type == 0
        if fc_type == 0:
            mgmt_count += 1
            src = wlan.ta if hasattr(wlan, 'ta') else '??'
            dst = wlan.ra if hasattr(wlan, 'ra') else '??'

            # Print all management frame subtypes for discovery
            if fc_subtype is not None:
                if fc_subtype in (13, 14):  # action, action no-ack
                    action_count += 1
                    print(f'[ACTION] subtype=0x{fc_subtype:02x} '
                          f'src={src} dst={dst}')

                    # Try to get category from wlan_mgt layer
                    if hasattr(pkt, 'wlan_mgt'):
                        for fname in pkt.wlan_mgt.field_names:
                            val = getattr(pkt.wlan_mgt, fname, None)
                            if val and fname != 'tagged_all':
                                print(f'  {fname}: {val}')

                    # Also check raw bytes for category
                    if hasattr(pkt, 'data'):
                        print(f'  raw_data: {pkt.data}')
                    print()

            # Also check wlan_mgt for category 21 or 30 regardless of subtype
            if hasattr(pkt, 'wlan_mgt'):
                cat = None
                for attr in ['fixed_category_code', 'category_code',
                             'fixed_action_code']:
                    if hasattr(pkt.wlan_mgt, attr):
                        try:
                            cat = int(getattr(pkt.wlan_mgt, attr))
                            break
                        except:
                            pass
                if cat in (21, 30):
                    bfi_count += 1
                    std = 'HE' if cat == 30 else 'VHT'
                    print(f'*** BFI-{std} *** cat={cat} src={src} dst={dst}')

    except Exception:
        continue

signal_handler(None, None)
