import subprocess
import os

def run_sql_injection(url, scan_id):
    log_file = f"logs/{scan_id}_sqlmap.txt"
    os.makedirs("logs", exist_ok=True)
    cmd = ["sqlmap", "-u", url, "--batch", "--level=2", "--risk=1"]
    with open(log_file, "w") as f:
        subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT)