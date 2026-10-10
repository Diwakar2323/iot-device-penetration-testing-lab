# IoT Device Penetration Testing Lab

A beginner-friendly Python project for an authorized IoT security lab.

## Objective
- Maintain an IoT device inventory
- Inspect authorized firmware files
- Review exported network observations
- Generate simple JSON security reports

## Tools
- Shodan: authorized asset research
- Wireshark: network traffic capture and analysis
- Kali Linux: controlled security testing environment
- Custom firmware analysis tools: firmware review

## Requirements
Python 3. No third-party Python packages are required.

## Run in VS Code

Device inventory:
`python iot_security_lab.py inventory samples/devices.csv`

Firmware inspection:
`python iot_security_lab.py firmware samples/sample_firmware.bin`

Network observation review:
`python iot_security_lab.py network samples/network_observations.csv`

Reports are created in `reports/`.

## Project structure
```text
iot-device-penetration-testing-lab/
├── iot_security_lab.py
├── README.md
├── requirements.txt
├── .gitignore
├── samples/
│   ├── devices.csv
│   ├── network_observations.csv
│   └── sample_firmware.bin
└── reports/
```

## Lab workflow
Use only devices, firmware and traffic that you own or have explicit permission to test. Keep the lab isolated. Use Wireshark for authorized captures, review authorized firmware with this project, and use Shodan only for authorized research.

## Limitations
This is an educational lab helper, not a full penetration-testing platform. Its findings are indicators for manual review and do not prove that a vulnerability exists.
