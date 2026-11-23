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

## Learning "healthy" from a separate set (--reference)
FlowLens decides that something is slow by comparing it with healthy captures.
By default, it learns what "healthy" looks like from the healthy captures in the set it is testing.
That is fine for a quick check.
For a fair test, though, FlowLens should not learn from the captures it is being scored on.

With `--reference`, FlowLens learns only from the healthy captures in another `measurements.csv`.
Every capture in the tested set, including its healthy ones, is used only for testing.

    # learn "healthy" from the pilot set, test on data/test
    python -m flowlens.run data/test --reference results/pilot_measurements.csv
    python -m flowlens.evaluate data/test/measurements.csv --reference results/pilot_measurements.csv --out results/test

- `run.py` uses the reference when it writes the `fl` column.
- `evaluate.py` runs FlowLens again with the reference, instead of using the `fl` column in the CSV.
- The reference must be a different file from the tested set; otherwise the command stops with an error.
- If the reference has fewer than 5 healthy captures, FlowLens prints a warning and uses built-in healthy values instead.
- Without `--reference`, nothing changes: the pilot results stay as they are.

## Folders
- flowlens/ : pcap reader, measurements, baseline B1, FlowLens (scorer.py)
- lab/      : lab setup, slow DNS / web servers, capture scripts
- report/   : reports
- results/  : graphs and tables
