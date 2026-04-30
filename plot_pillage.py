import os
import glob
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# --- Configuration ---
DATA_DIR = 'trials' 

def parse_iperf_json(filepath):
    """Extracts the time and throughput (in Mbps) for each second from the iperf3 JSON."""
    data = None
    
    # PowerShell redirects use UTF-16. Try that first, fallback to UTF-8.
    try:
        with open(filepath, 'r', encoding='utf-16') as f:
            data = json.load(f)
    except UnicodeError:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            print(f"[!] Skipping {filepath} - Failed UTF-8 decode: {e}")
            return None, None
    except json.JSONDecodeError:
        print(f"[!] Skipping {filepath} - Invalid JSON")
        return None, None

    times = []
    mbps = []

    if data and 'intervals' in data:
        for interval in data['intervals']:
            if 'sum' in interval:
                t = interval['sum']['start']
                bps = interval['sum']['bits_per_second']
                times.append(t)
                mbps.append(bps / 1_000_000) # Convert to Megabits per second
                
    return times, mbps

def main():
    print("[*] Parsing iperf3 JSON files...")
    
    series_data = {
        'Unforged (Control)': [],
        'Random Forgery': [],
        'Optimal (SU-Pillage)': []
    }
    
    patterns = {
        'Unforged (Control)': '*copy*.json',
        'Random Forgery': '*random*.json',
        'Optimal (SU-Pillage)': '*optimal*.json'
    }

    for condition, pattern in patterns.items():
        files = glob.glob(os.path.join(DATA_DIR, pattern))
        for f in files:
            t, m = parse_iperf_json(f)
            if t and m:
                series_data[condition].append((t, m))
                
    print(f"[*] Loaded {len(series_data['Unforged (Control)'])} Unforged, "
          f"{len(series_data['Random Forgery'])} Random, "
          f"{len(series_data['Optimal (SU-Pillage)'])} Optimal trials.")

    sns.set_theme(style="whitegrid")
    colors = {'Unforged (Control)': 'green', 'Random Forgery': 'orange', 'Optimal (SU-Pillage)': 'red'}

    # ==========================================
    # GRAPH 1: Averaged Time-Series Line Graph
    # ==========================================
    plt.figure(figsize=(10, 6))
    
    for condition in series_data:
        trials = series_data[condition]
        if not trials:
            continue
            
        # Find the minimum length of the trials to align them properly
        min_len = min(len(m_list) for t_list, m_list in trials)
        
        # Stack all the trials on top of each other in a 2D Numpy array
        stacked_mbps = np.array([m_list[:min_len] for t_list, m_list in trials])
        
        # Calculate the MEDIAN throughput for each second across all 10 trials
        median_mbps = np.median(stacked_mbps, axis=0)
        time_axis = np.arange(min_len) # Creates an array [0, 1, 2, ..., min_len-1]
        
        plt.plot(time_axis, median_mbps, label=condition, color=colors[condition], linewidth=2.5)

    plt.title('SU-MIMO Pillage Attack: Median Throughput (Aggregated 10 Trials)', fontsize=14)
    plt.xlabel('Time (Seconds)', fontsize=12)
    plt.ylabel('Throughput (Mbps)', fontsize=12)
    plt.legend()
    plt.tight_layout()
    plt.savefig('pillage_timeseries_median.png', dpi=300)
    print("[+] Saved time-series graph as 'pillage_timeseries_median.png'")

    # ==========================================
    # GRAPH 2: Distribution Box-Plot
    # ==========================================
    distribution_records = []
    
    for condition in series_data:
        for t_list, m_list in series_data[condition]:
            attack_window_mbps = []
            for t, m in zip(t_list, m_list):
                # We use 15s to 50s here to account for your slightly later manual start times!
                if 15 <= t <= 50: 
                    attack_window_mbps.append(m)
            
            if attack_window_mbps:
                avg_during_attack = sum(attack_window_mbps) / len(attack_window_mbps)
                distribution_records.append({'Condition': condition, 'Avg Throughput (Mbps)': avg_during_attack})

    df = pd.DataFrame(distribution_records)

    plt.figure(figsize=(8, 6))
    sns.boxplot(x='Condition', y='Avg Throughput (Mbps)', data=df, palette=colors.values())
    sns.stripplot(x='Condition', y='Avg Throughput (Mbps)', data=df, color='black', alpha=0.5, jitter=True)
    
    plt.title('Distribution of Throughput During Attack Window (15-50s)', fontsize=14)
    plt.ylabel('Average Throughput (Mbps)', fontsize=12)
    plt.xlabel('')
    plt.tight_layout()
    plt.savefig('pillage_distribution.png', dpi=300)
    print("[+] Saved distribution graph as 'pillage_distribution.png'")

if __name__ == '__main__':
    main()
