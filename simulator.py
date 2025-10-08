# simulator_writer.py
import time, os, random, string
out_dir = os.path.join(os.path.expanduser("~"), "temp_key_sim")
os.makedirs(out_dir, exist_ok=True)
outfile = os.path.join(out_dir, "input_log.txt")
print("Simulator will append to:", outfile)
try:
    while True:
        s = ''.join(random.choices(string.ascii_lowercase + " ", k=32))
        with open(outfile, "a") as f:
            f.write(s + "\n")
        time.sleep(2)  # writes every 2 seconds
except KeyboardInterrupt:
    print("Simulator stopped")
