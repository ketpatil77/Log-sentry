import time
from app.services.analyzer import analyze_text

def run(n=10000):
    lines=[f'10.0.0.{i%250+1} - - [06/Sep/2026:18:{i%60:02d}:{i%60:02d} +0000] "GET /health HTTP/1.1" 200 12' for i in range(n)]
    t=time.perf_counter(); analyze_text('\n'.join(lines)); elapsed=time.perf_counter()-t
    print(f"events={n} seconds={elapsed:.4f} events_per_second={n/elapsed:.0f}")
if __name__=='__main__': run()
