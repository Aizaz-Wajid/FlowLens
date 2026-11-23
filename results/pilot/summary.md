# Pilot results: B1 vs FlowLens

The pilot set has 80 lab captures: 20 healthy, plus 15 each of DNS, delay, server and loss faults.
79 are scored. run0041 is left out because it was a loss run where no packet was actually lost.
The numbers come from `python -m flowlens.evaluate` and the graphs from `python -m flowlens.plots`.

## Overall

| Method   | Top-1 accuracy | 95% CI (Wilson) | False alarms (healthy runs) | 95% CI (Wilson) |
|----------|---------------:|----------------:|----------------------------:|----------------:|
| B1       | 81.0% (64/79)  | 71.0% – 88.1%   | 0/20 (0%)                   | 0% – 16.1%      |
| FlowLens | 97.5% (77/79)  | 91.2% – 99.3%   | 0/20 (0%)                   | 0% – 16.1%      |

## F1 per cause

| Cause   | B1   | FlowLens |
|---------|-----:|---------:|
| healthy | 0.73 | 1.00     |
| dns     | 0.80 | 0.94     |
| delay   | 0.80 | 1.00     |
| server  | 0.80 | 1.00     |
| loss    | 1.00 | 0.92     |

## McNemar's test (exact)

| Both right | Only B1 right | Only FlowLens right | Both wrong | p-value |
|-----------:|--------------:|--------------------:|-----------:|--------:|
| 62         | 2             | 15                  | 0          | 0.0023  |

FlowLens is right on 15 captures where B1 is wrong. B1 is right on only 2 where FlowLens is wrong.
This difference is statistically significant (p < 0.01).

Graphs: `f1_compare.png`, `b1_confusion.png`, `fl_confusion.png`, `delay_breakdown.png`.

## Why B1 fails and FlowLens does better

B1 uses fixed limits. DNS is "slow" only above 200 ms, the link only above 100 ms RTT, and the server only above 300 ms wait.
In the lab, a healthy visit has under 1 ms of DNS and about 2 ms of server wait.
So a mild fault can make a step 50 to 100 times slower and still stay under B1's limits.
For example, the missed runs had 100 ms DNS, 50 ms RTT or 200 ms server wait.
B1 labelled all 15 of these mild runs "healthy" (5 DNS, 5 delay, 5 server).
FlowLens first learns what "healthy" looks like from the healthy captures (median and spread).
It then flags any step that is far outside that normal range.
Because the lab's normal times are so small, even a mild slowdown stands out clearly.
FlowLens caught every DNS, delay and server fault, and it still raised no false alarms on the 20 healthy runs.

## Known limit: loss that hits DNS (run0030, run0060)

FlowLens got two loss runs wrong and called them "dns".
In both, the injected packet loss also dropped the DNS query.
The client waited the 5-second resolver timeout and then asked again.
DNS really was the slowest part of these visits (5.0 s out of 5.0–6.0 s total).
FlowLens names the step that took the most time, so it reported DNS.
The real root cause, however, was packet loss.
FlowLens currently cannot tell a slow DNS server apart from a lost DNS packet.
B1 got these two right only because it flags any retransmission as loss.
A possible fix is to treat a DNS time close to the resolver timeout (about 5 s) as evidence of loss.
