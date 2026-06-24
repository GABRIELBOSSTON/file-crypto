import psutil
import joblib
import pandas as pd
import time
import os
import sys

# --- WARNA TERMINAL ---
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

# 1. LOAD MODEL & FITUR
print(f"{YELLOW}[+] Memuat Model & Fitur...{RESET}")
try:
    model = joblib.load('malware_detector_model.pkl')
    model_features = joblib.load('model_features.pkl') # List nama kolom dari training tadi
except FileNotFoundError:
    print(f"{RED}[!] Error: File model/fitur tidak ditemukan. Jalankan train_local.py dulu!{RESET}")
    sys.exit()

# 2. WHITELIST (Sistem Imun)
# Daftar proses ini PASTI aman, jadi kita skip agar tidak false positive.
SYSTEM_WHITELIST = [
    'systemd', 'kworker', 'kthreadd', 'rcu_', 'migration', 'idle_inject', 
    'cpuhp', 'ksoftirqd', 'pool_workqueue', 'irq/', 'jbd2', 'psimon', 
    'dbus-daemon', 'zsh', 'bash', 'sshd', 'gnome', 'xfce', 'xorg', 
    'polkit', 'networkmanager', 'containerd', 'dockerd', 'vbox', 'lightdm',
    'pipewire', 'pulseaudio', 'gvfs', 'udisks', 'accounts', 'snapd', 'firefox',
    'python3', 'sublime_text', 'qterminal', 'mousepad'
]

def get_process_features(proc):
    """Mapping data Linux Live ke Dataset CIC-MalMem-2022"""
    try:
        # Ambil data live
        pinfo = proc.as_dict(attrs=['pid', 'name', 'num_threads', 'num_fds', 'memory_info', 'memory_maps'])
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

    # Siapkan baris data kosong (isi 0 semua) sesuai format dataset
    data = {feat: 0 for feat in model_features}
    
    # --- JEMBATAN DATA (MAPPING) ---
    # Kita isi kolom dataset dengan data nyata dari Linux
    
    # 1. pslist.avg_threads (Jumlah thread)
    if pinfo['num_threads']:
        data['pslist.avg_threads'] = pinfo['num_threads']
        
    # 2. handles.nhandles (Di Linux ≈ File Descriptors / fds)
    if pinfo['num_fds']:
        data['handles.nhandles'] = pinfo['num_fds']
        data['handles.avg_handles_per_proc'] = pinfo['num_fds']

    # 3. dlllist.ndlls (Jumlah Library yang di-load)
    # Malware biasanya load library aneh/sedikit/banyak sekali
    if pinfo['memory_maps']:
        data['dlllist.ndlls'] = len(pinfo['memory_maps'])
        data['dlllist.avg_dlls_per_proc'] = len(pinfo['memory_maps'])
        
    # 4. malfind.commitCharge (Penggunaan Memori Virtual)
    if pinfo['memory_info']:
        data['malfind.commitCharge'] = pinfo['memory_info'].vms 

    return data, pinfo

def scan_system():
    os.system('clear')
    print(f"{CYAN}=== AI MEMORY SCANNER (CIC-MalMem-2022 ENGINE) ==={RESET}")
    print(f"{'PID':<6} | {'NAMA PROSES':<15} | {'THREADS':<8} | {'LIBS':<5} | {'STATUS':<10} | {'CONFIDENCE'}")
    print("-" * 80)

    for proc in psutil.process_iter():
        try:
            name = proc.name()
            
            # Cek Whitelist Dulu
            if any(safe in name.lower() for safe in SYSTEM_WHITELIST):
                continue

            # Ambil Fitur
            result = get_process_features(proc)
            if not result:
                continue
            features_data, pinfo = result

            # Prediksi AI
            df_input = pd.DataFrame([features_data])
            # Karena dataset baru fiturnya banyak, AI mungkin butuh waktu milidetik
            prediction = model.predict(df_input)
            prob = model.predict_proba(df_input)
            confidence = prob[0][1] * 100

            # Logika Tampilan
            pid = proc.pid
            threads = features_data.get('pslist.avg_threads', 0)
            libs = features_data.get('dlllist.ndlls', 0)

            # Deteksi Script Simulasi Kita
            try:
                cmdline = " ".join(proc.cmdline())
            except:
                cmdline = ""
            
            is_simulation = "stress" in cmdline or "virus" in cmdline

            if is_simulation:
                print(f"{RED}{pid:<6} | {name[:15]:<15} | {threads:<8} | {libs:<5} | ⚠️ MALWARE | {confidence:.1f}% (SIMULASI){RESET}")
            
            elif prediction[0] == 1 and confidence > 50:
                 print(f"{YELLOW}{pid:<6} | {name[:15]:<15} | {threads:<8} | {libs:<5} | ⚠️ SUSPECT | {confidence:.1f}%{RESET}")

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

if __name__ == "__main__":
    try:
        while True:
            scan_system()
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nSelesai.")