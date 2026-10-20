# Datasets

The training data is **not committed** to this repository (it is large and
licensed for research use). Download it yourself into this folder.

## CIC-IDS2017

- Source: Canadian Institute for Cybersecurity (University of New Brunswick)
  <https://www.unb.ca/cic/datasets/ids-2017.html>
- Download the **"MachineLearningCSV"** archive (the pre-extracted flow CSVs).
- Extract the CSV files directly into this directory:

  ```
  ml/datasets/
    Monday-WorkingHours.pcap_ISCX.csv
    Tuesday-WorkingHours.pcap_ISCX.csv
    Wednesday-workingHours.pcap_ISCX.csv
    Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
    ...
  ```

`train.py` reads every `*.csv` in this folder, concatenates them, maps the CIC
flow columns onto the shared feature schema (`ml/features.py:FEATURE_NAMES`),
and trains the classifier + IsolationForest.

## Notes

- Each CSV must keep its header row; `train.py` strips whitespace from column
  names, so the usual leading-space quirk (e.g. `" Label"`) is handled.
- Only the columns referenced in `features.cic_row_to_features` are used; extra
  columns are ignored.
- `.csv` files here are git-ignored (see `recon-tool/.gitignore`). Do not commit
  them.

## Licensing / ethics

CIC-IDS2017 is provided for research and educational use. Cite the dataset in
any report. This project uses it strictly for an authorized academic lab.
