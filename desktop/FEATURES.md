# DFIP Investigator Desktop — Function Matrix

| Function | Desktop role | Status |
|---|---|---|
| Login / RBAC | Secure backend session | Integrated with existing DFIP API |
| Case management | Local + synchronized case work | Local offline-ready case creation + web sync |
| Evidence acquisition | Preserve original and hash | Native non-overwrite copy + SHA-256 |
| Evidence preservation | Prevent accidental writes | Native read-only permission |
| E01/RAW/DD/AFF/AFF4 | Forensic image workflow | Backend engine + native adapter boundary |
| Partition analysis | mmls | Allow-listed native tool bridge |
| Filesystem analysis | fsstat/fls | Allow-listed native tool bridge |
| Inode examination | istat | Allow-listed native tool bridge |
| File recovery | icat | Allow-listed native tool bridge |
| Metadata | ExifTool | Allow-listed native tool bridge |
| Malware rules | YARA | Allow-listed native tool bridge |
| Strings | strings | Allow-listed native tool bridge |
| File identification | file | Allow-listed native tool bridge |
| PCAP | tshark | Allow-listed native tool bridge |
| Memory | Volatility | Allow-listed native tool bridge |
| Jobs | Long-running analysis | Existing backend durable jobs |
| Timeline | Event review | Existing backend module |
| Findings | Investigation conclusions | Existing backend module |
| Reports | Export and integrity | Existing backend module |
| Chain of custody | Provenance | Existing backend module |
| Audit | Tamper-evident log | Existing backend module |
| Offline workspace | Work without network | Local case manifest + evidence workspace |
| Tool timeout | Prevent runaway process | Native bounded execution |
| Device acquisition | Physical devices | Adapter boundary; provider-specific implementation required |
| Windows-only distribution | Native installer scope | Out of scope: macOS/Linux desktop builds, mobile apps |
