import subprocess
import time

# Start the process
process = subprocess.Popen(["virus.exe"])

# Wait for the process to finish and capture its output
while process.poll() is None:
    print("Waiting for virus.exe to finish...")
    time.sleep(1)  # wait for 1 second before checking again

stdout, stderr = process.communicate()

# Print the output, if any
print("stdout:", stdout)
print("stderr:", stderr)

# Check the return code to see if the process completed successfully
if process.returncode == 0:
    print("Process completed successfully.")
else:
    print("Process failed with return code:", process.returncode)