# File: stress_test.py
import time
data = []
print("Menjalankan simulasi anomali memori...")
while True:
    data.append(' ' * 10**7) # Menambah beban memori 10MB terus menerus
    time.sleep(0.5)