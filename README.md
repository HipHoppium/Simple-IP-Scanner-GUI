# IP Scanner GUI Tool

A basic Python-based GUI tool to scan IP addresses or ranges using Nmap. Built for internal use during an internship.

## Features

- GUI built with `tkinter`
- Lets you set custom scan targets (single IP, multiple IPs, or CIDR)
- Finds live hosts and displays them with status colors
- Logs results to `ipmac.txt`
- Option to discover and add new hosts over time

## Requirements

- Python 3
- [Nmap](https://nmap.org/) installed and available in system PATH
- Python modules:
  - `python-nmap`
  - `tkinter` (comes with most Python installations)

Install the required module with:

```bash
pip install python-nmap
```

## How to Run

```bash
python ip_scanner_gui.py
```

Then use the GUI:
- Click **Set Scan Target** to enter IPs or ranges
- Use **Start Scan** to scan and see results
- **Find New Hosts** detects any new active IPs
- **Clear Labels** resets the display

## Notes

This tool was made quickly to help during an internship project. It's nothing fancy, but it works well for small LANs or quick checks.
