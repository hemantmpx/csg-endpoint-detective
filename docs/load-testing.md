# Load testing

`load-tests/classroom_load_test.py` drives independent session cookies through join, timeline, broad and filtered searches, event detail, evidence selection, and submission. It reports throughput, error percentage, and latency percentiles. The expected target is 50 concurrent users for ten minutes, with event-search API p95 below 500 ms. Run after the corpus has been seeded and the app is reachable. Record host/container resources and actual results alongside any performance claim; a script definition alone is not evidence of a successful load run.
