import math
import time
from threading import Lock

class Bucket:
    def __init__(self, fill_interval, capacity):
        self.start_time = time.time()
        self.capacity = capacity
        self.quantum = 1
        self.fill_interval = fill_interval
        self.mu = Lock()
        self.available_tokens = capacity
        self.latest_tick = 0

    def take(self, count):
        self.mu.acquire()
        try:
            now = time.time()
            tick = self.current_tick(now)
            self.adjust_available_tokens(tick)
            avail = self.available_tokens - count
            if avail >= 0:
                self.available_tokens = avail
                return 0
            end_tick = tick + (-avail + self.quantum - 1) // self.quantum
            end_time = self.start_time + end_tick * self.fill_interval
            wait_time = end_time - now
            return max(0, wait_time)
        finally:
            self.mu.release()

    def current_tick(self, now):
        return int((now - self.start_time) / self.fill_interval)

    def adjust_available_tokens(self, tick):
        last_tick = self.latest_tick
        self.latest_tick = tick
        if self.available_tokens >= self.capacity:
            return
        self.available_tokens += (tick - last_tick) * self.quantum
        if self.available_tokens > self.capacity:
            self.available_tokens = self.capacity

def main():
    fill_interval = 250 / 1000  # 250 milliseconds in seconds
    capacity = 10
    bucket = Bucket(fill_interval, capacity)
    tokens_to_take = 1

    while True:
        wait_time = bucket.take(tokens_to_take)
        if wait_time == 0:
            print("Tokens taken successfully.")
        else:
            print(f"Waiting for {wait_time} seconds.")
            time.sleep(wait_time)

if __name__ == "__main__":
    main()
