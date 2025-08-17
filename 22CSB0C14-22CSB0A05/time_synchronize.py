import time

epoch = int(time.time())
print(f"Initial wall clock epoch: {epoch}")

with open("epoch.txt", "w") as f:
    f.write(str(epoch))
