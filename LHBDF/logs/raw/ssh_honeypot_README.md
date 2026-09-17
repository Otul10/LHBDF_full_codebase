# Dataset Specification: SSH Interactive Honeypot Logs

## General Information

This repository archives the custom modular multi-threaded SSH honeypot framework used to collect the dataset for the associated research. Developed in Python 3.10 and utilizing the Paramiko library, the software simulates an interactive SSHv2 Debian environment, capturing session metadata, authentication attempts, and post-authentication command payloads in real time.

- Version: 2.3 (Supplemental Metadata Release)
- Dataset Name: Interactive SSH Attack & Payload Dataset (honey.db)
- Collection Period: July 27, 2025 – November 14, 2025 (4 months)
- Total Records: 145,425 events (after refinement)
- Data Source: Custom multi-threaded SSH Honeypot (Paramiko-based)
- Format: SQLite 3 (.db) / CSV (.csv) / Metadata (.csv)

## Data and Article Association Note:

This software framework is a companion tool for the dataset and peer-reviewed article published in Data in Brief.

## Revision History


### Version 2.3 (Current)

- Updated metadata release.
- Harmonized versioning between `README.md` and BibTeX records.

### Version 2.2

Supplemental Metadata Release.

- Added file `geospatial_attack_distribution.csv` featuring geolocation and organizational data (via ipinfo.io) for all unique IPs in the dataset.
- Standardized filenames by removing version suffixes (e.g., `honey_db.tar.gz` instead of `honey_db_v2.1.tar.gz`) to ensure persistent links.
- No changes were made to the core traffic logs from v2.1.
- Corrected the `README.md` and BibTeX records to match the physical database state.


### Version 2.1

- Physically updated the level column in the database to align with industry standards. INFO now represents transport-layer noise (94.6%), and WARNING marks active application-layer interactions (5.4%).
- Corrected the dataset duration from 6 to 4 months in all documentation to match the actual refined data window (July–Nov 2025).
- Confirmed a total of 145,425 records after the final purging of inconsistent session markers.
- Corrected the `README.md` and BibTeX records to match the physical database state.

### Version 2.0

- Removed 74 internal administrative sessions (localhost/127.0.0.1).
- Excluded initial debugging logs from May–July 2025 to ensure 100% external threat actor telemetry.

### Version 1.0

- Initial Release - raw unrefined dataset covering the full 6-month deployment.

## Temporal Analysis

The data collection focuses on a 4-month intensive observation window:

-  Start Date: July 27, 2025, 07:16 UTC
-  End Date: November 14, 2025, 00:57 UTC
-  Peak Intensity: Observed at 13:00 UTC daily, with 10,700+ interactions per hour during spikes.

## Data Schema & Dictionary

The database consists of a primary table `honey` with the following structure:

| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | INTEGER | Primary key. |
| `timestamp` | DATETIME | Event time in ISO 8601 format. |
| `session_id` | UUID | Unique session identifier for Kill Chain reconstruction. |
| `ip` | TEXT | Source IPv4 address of the attacker. |
| `port` | INTEGER | Attacker's source port. |
| `event_type` | TEXT | Event class: `SSH connect`, `SSH login`, `exec_command`. |
| `message` | TEXT | Detailed log (e.g., specific login/password pairs). |
| `command` | TEXT | The exact shell command string entered by the attacker. |
| `level` | TEXT | Logging level: `INFO` (transport/connections), `WARNING` (application/attack actions). |

## Key Findings & Research Value (Updated v2.1)

- The dataset captures the full post-authentication lifecycle, including 28 interactive commands (e.g., rare file-less exploitation via /dev/tcp bash sockets) originating from unique threat actors.
- Records 2,109 unique credential pairs from modern automated brute-force patterns.
- Pre-filtered level field allows researchers to immediately isolate attack payloads (5.4% of data) from background noise.


## Ethical Considerations & Anonymization

All captured data is for research purposes only. IP addresses included in the raw logs represent active threat actors (botnets and scanners). For public distribution, sensitive network metadata has been preserved to allow for ASN and GeoIP correlation.

## Authors & Contribution

Viktor Boiko (ORCID: 0000-0001-5929-657X) — Scientific Supervisor & Lead Researcher, Data Curation, Validation. Associate Professor at the Department of Cybersecurity.

Oleksandr Niiakyi (ORCID: 0009-0005-1025-1617) — Software Developer & Researcher.

Affiliation: Faculty of Cybersecurity and Information Technologies, National University "Odesa Law Academy".
https://ror.org/0282prk66

## Citation

If you use this dataset, please cite it as follows:

    @dataset{boiko_2026_ssh_honey,
      author       = {Boiko, Viktor and Niiakyi, Oleksandr},
      title        = {{A 4-Month Dataset of SSH Botnet Interactions and Command Payloads (Version 2.3)}},
      month        = apr,
      year         = 2026,
      publisher    = {Zenodo},
      version      = {2.3},
      doi          = {10.5281/zenodo.19629700},
      url          = {https://doi.org/10.5281/zenodo.19629700}
    }

## Primary References

Main Article:

Boiko, V., & Niiakyi, O. (2026). Data in Brief. DOI: https://doi.org/10.1016/j.dib.2026.112860

Dataset:

Boiko, V., & Niiakyi, O. (2026). Zenodo. DOI: https://doi.org/10.5281/zenodo.19629700
