# Simpan sebagai: train_cic.py
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import os

# Nama file dataset dari Kaggle
FILE_NAME = 'Obfuscated-MalMem2022.csv'

print(f"[1/5] Membaca Dataset '{FILE_NAME}'...")
if not os.path.exists(FILE_NAME):
    print(f"    [!] Error: File '{FILE_NAME}' tidak ditemukan di folder ini.")
    print("    [!] Pastikan kamu sudah upload filenya ke folder project.")
    exit()

df = pd.read_csv(FILE_NAME)
print(f"    -> Berhasil! Total Data: {len(df)} baris")

# [2/5] Pembersihan Data (Preprocessing)
print("[2/5] Menyiapkan Data...")

# Target kita adalah kolom 'Class' (Benign / Malware)
# Kita ubah jadi angka: Benign=0, Malware=1
le = LabelEncoder()
df['Class'] = le.fit_transform(df['Class'])

# Hapus kolom 'Category' (karena itu teks detail tipe virus, kita cuma butuh tahu Jahat/Tidak)
# Hapus juga 'Class' dari fitur (karena itu jawaban kuncinya)
X = df.drop(['Class', 'Category'], axis=1)
y = df['Class']

# Simpan nama-nama kolom fitur agar scanner nanti tahu urutannya
feature_names = X.columns.tolist()
joblib.dump(feature_names, 'model_features.pkl')

print(f"    -> Memakai {len(feature_names)} fitur untuk deteksi.")

# [3/5] Membagi Data Ujian
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# [4/5] Melatih AI
print("[4/5] Melatih Otak AI (Random Forest)...")
# n_jobs=-1 artinya pakai semua core CPU biar cepat
model = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# [5/5] Menyimpan Model
print("[5/5] Menyimpan Model ke File...")
joblib.dump(model, 'malware_detector_model.pkl')
print("\n[SUKSES] Model 'malware_detector_model.pkl' siap digunakan!")