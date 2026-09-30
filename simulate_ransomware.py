# ===== simulate_ransomware.py - hits a canary early on purpose =====
import os
import time

TARGET = r"C:\RansomwareLab\testdata"

print("Attacking ONLY:", TARGET)

names = sorted(os.listdir(TARGET))        # _canary_ files sort first

for name in names:
    if name.endswith(".locked"):
        continue

    path = os.path.join(TARGET, name)

    with open(path, "r", errors="ignore") as f:
        text = f.read()

    with open(path, "w") as f:
        f.write(text[::-1])               # "encryption" = write the text back reversed

    os.rename(path, path + ".locked")

    print("touched", name)
    time.sleep(0.3)                       # slow enough to read the order

print("done")