# NetFortress🛡️ | Intrusion Detection System (IDS)🛡️

![License](https://img.shields.io/github/license/Nav3h/NetFortress)
![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)
![Maintenance](https://img.shields.io/maintenance/yes/2023)

## Overview

The Intrusion Detection System (IDS) is a sophisticated network security solution designed to protect your network infrastructure against unauthorized access, suspicious activities, and potential security threats. Leveraging Python and a range of robust libraries, this system offers real-time monitoring, intelligent threat detection, and customizable alerts to enhance your network's security posture.

## Features

- **Real-time Network Monitoring:** Continuously monitors network traffic for suspicious behavior.
- **Advanced Threat Detection:** Identifies common attack patterns, including SYN floods, port scanning, ping sweeping, bruteforce and data exfiltration.
- **Flexible Alerting:** Provides customizable alerts and notifications to keep you informed.
- **Extensible Architecture:** Easily extend and customize detection methods to adapt to evolving threats.

## Table of Contents

- [Installation](#installation)
- [Dependencies](#dependencies)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Installation

To deploy the IDS on your system, follow these installation steps:

1. **Clone the Repository:**

    ```bash
    git clone https://github.com/Nav3h/NetFortress.git
    ```

2. **Navigate to the Project Directory:**

    ```bash
    cd IDS
    ```

3. **Install Dependencies:**

    Ensure you have the required dependencies installed. You can install them using pip:

    ```bash
    pip install -r requirements.txt
    ```

4. **Configuration:**

    Configure the system settings and detection rules by modifying the `config.ini` file.

5. **Run the IDS:**

    Execute the following command to start monitoring your network:

    ```bash
    python main.py
    ```

## Dependencies

The IDS relies on the following Python libraries and packages:

- [Scapy](https://scapy.net/) - For packet manipulation and network scanning.
- [Colorama](https://pypi.org/project/colorama/) - For enhancing command-line output.


Ensure you have Python 3.9 or higher installed on your system.

## Contributing

contributions are welcomed. If you have ideas for improvements, bug fixes, or new features, please consider opening an issue or submitting a pull request. 

## License

This project is open-source and licensed under the MIT License. You are encouraged to review the license for usage rights and permissions.
