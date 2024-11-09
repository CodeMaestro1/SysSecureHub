# Overview

This project implements a custom malware detection system using a signature database to identify and quarantine malicious files.

## Definition

A *malicious file* is defined as any file whose metadata (e.g., SHA256 hash, etc.) has been categorized as a threat by the cybersecurity community.

---

## Task A: Signature Database and Detection

### Implementation Details

To build a signature malware database using real data, we leverage APIs from [MalwareBazaar](https://bazaar.abuse.ch/api/) and [Hybrid Analysis](https://www.hybrid-analysis.com/docs/api/v2):

- **MalwareBazaar API**: Fetches malware signatures based on specific tags (details available in `config.py`).
- **Hybrid Analysis API**: Classifies the threat level of the fetched malware samples. The severity levels are determined based on the `threat_score` returned:
  - A score of **1** indicates a *low severity*.
  - A score of **2** indicates a *medium severity*.
  - A score of **3** (maximum) indicates a *high severity*.

**Note**:

- Some entries may be new and unclassified. Such entries are labeled as *Unknown* for their severity level.
- Fake malicious data is also generated for testing purposes. We use the famous EICAR test file and manually created "fake-malware" files. Although the term *fake-malware* is not entirely accurate, it was useful during testing. The fake malware is purposefully given a high severity level, but you can adjust this as needed.

---

## Task B: Search and Quarantine

To facilitate testing, we generate a directory containing both malicious and benign files using the `create_directory_with_files` function, which creates nested directories and files.

### Quarantine Implementation

Malicious files are moved to a designated quarantine folder. Ideally, for enhanced security, we would zip and encrypt the quarantine folder. However, due to time constraints, this feature has not been implemented.

---

## Task C: Real-Time Monitoring and Anomaly Detection

This task implements a real-time monitoring tool using Python’s `watchdog` library. The tool continuously monitors a specified directory for any changes and automatically quarantines any newly detected malicious files.

---

## Usage

You can run each script individually for testing or execute the `main.py` script to run all parts of the application together. **Note**: To generate a new signature malware file, ensure you have the necessary accounts set up and that the environment variables for API keys are accessible.

### How to Run

To run the program, execute the `main.py` script with the appropriate arguments.

---

## Prerequisites

Ensure that the following libraries are installed on your system before executing the program:

- `numpy`
- `watchdog`
- `tabula`

You can install them using `pip` if necessary:

```bash
pip install numpy watchdog tabula
```

---

## Configuration (`config.py`)

The `config.py` file contains global variables used throughout the project. You can modify these variables to adjust the behavior of the system according to your needs.

---

## References

- [MalwareBazaar API](https://bazaar.abuse.ch/api/)
- [Hybrid Analysis API](https://www.hybrid-analysis.com/docs/api/v2)

---
