# FlowLens
Finds the root cause of slow web visits from packet captures.
EE-353 Computer Networks, NUST SEECS. Muhammad Aizaz Wajid, Amna Mirza.

## Setup (Ubuntu / WSL)
    python3 -m venv ~/flenv && source ~/flenv/bin/activate
    pip install -r requirements.txt
    sudo apt install -y tcpdump tshark ethtool curl dnsutils

## Run
    sudo ./lab/lab_setup.sh                                  # create client + server
    sudo ./lab/run_one.sh test run001 dns high small         # one labelled capture
    sudo ./lab/run_batch.sh pilot 5 small                    # many captures
    python -m flowlens.run data/pilot                        # measure + B1 + FlowLens + scores
    python -m flowlens.evaluate data/pilot/measurements.csv # B1 vs FlowLens: F1, false alarms, McNemar

## Folders
- flowlens/ : pcap reader, measurements, baseline B1, FlowLens (scorer.py)
- lab/      : lab setup, slow DNS / web servers, capture scripts
- report/   : reports
- results/  : graphs and tables
