# Windows Registry Security Scanner

## Overview

The **Windows Registry Security Scanner** is a Python-based tool designed to analyze Windows registry hives for potential security issues and suspicious configurations. It checks for misconfigurations, unauthorized modifications, and indicators of malicious activity in critical registry paths, such as auto-run entries, services, Winlogon settings, and more. The tool also integrates with VirusTotal for file hash analysis and generates detailed JSON reports for identified issues.

This tool is intended for security researchers, system administrators, and forensic analysts to detect potential threats and ensure system integrity.

## Features

- **Auto-Run Analysis**: Scans `Run` and `RunOnce` registry keys for suspicious entries, including checks for temporary directory execution and random naming patterns.
- **Service Validation**: Verifies Windows services for invalid signatures and non-standard paths, with optional VirusTotal hash checks.
- **Winlogon Checks**: Detects unauthorized modifications to critical Winlogon keys, such as `Shell`, `Userinit`, and `AutoAdminLogon`.
- **AppInit DLL Monitoring**: Identifies changes to `AppInit_DLLs` and `LoadAppInit_DLLs` for potential DLL injection risks.
- **Task Manager and Registry Tools**: Alerts on disabled Task Manager or Registry Tools, which may indicate malicious activity.
- **UAC and Windows Defender Monitoring**: Detects disabled User Account Control (UAC) and suspicious Windows Defender registry entries.
- **Firewall Settings**: Checks for disabled firewall settings in Domain and Standard profiles.
- **JSON Output**: Generates structured JSON reports (`alarms.json` and optional `signs.json`) for easy analysis and integration.
- **VirusTotal Integration**: Queries VirusTotal API for file hash analysis to identify potentially malicious executables.

## Prerequisites

To use the Windows Registry Security Scanner, ensure you have the following:

- **Python 3.8+**: Required to run the script.
- **Dependencies**:
  - Install required Python packages:
    ```bash
    pip install -r requirements.txt
    ```
  - Required packages: `argparse`, `pathlib`, `registry`, `subprocess`, `json`, `re`.
- **VirusTotal API Key**: A valid API key for querying file hashes (stored in a text file).
- **Windows Registry Hive File**: A registry hive file (e.g., `SYSTEM`, `SOFTWARE`) for analysis.
- **PowerShell**: Required for file hash and signature checks (Windows environment only).
- **freq.py**: A frequency analysis module (`freqtable2018.freq`) for detecting random naming patterns in executables.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/<your-username>/windows-registry-security-scanner.git
   cd windows-registry-security-scanner
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Ensure the `freqtable2018.freq` file is present in the project directory for frequency analysis.

4. Obtain a VirusTotal API key and save it in a text file (e.g., `vt_api_key.txt`).

## Usage

Run the tool with the following command-line arguments:

```bash
python scanner.py -r <registry_hive_path> -A <api_key_file> [-D <output_directory>] [-S <signs_directory>]
```

### Arguments

- `-r, --registry`: (Required) Path to the Windows registry hive file to analyze.
- `-A, --api`: (Required) Path to the text file containing the VirusTotal API key.
- `-D, --directory`: (Optional) Directory to store the output `alarms.json` file. Defaults to `./Output` in the current working directory.
- `-S, --signs`: (Optional) Directory to store the `signs.json` file for service signature information.

### Example

```bash
python scanner.py -r SYSTEM -A vt_api_key.txt -D output -S signs
```

This command:
- Analyzes the `SYSTEM` registry hive.
- Uses the API key from `vt_api_key.txt`.
- Saves output to the `output/alarms.json` file.
- Saves service signature information to `signs/signs.json`.

## Output

The tool generates two JSON files:

1. **alarms.json**: Contains alerts for detected issues, categorized by sections such as:
   - `Run Upon Startup`: Suspicious auto-run entries.
   - `Not Valid Service`: Invalid or unsigned services.
   - `Winlogon`: Modified Winlogon keys.
   - `AppInit`, `TSK | REG`, `UAC`, `Windows Defender`, `Firewall`: Issues in respective areas.

2. **signs.json** (optional): Stores information about signed and unsigned services, including paths, signatures, and thumbprints.

### Sample alarms.json

```json
{
    "Run Upon Startup": [
        {
            "Name": "SuspiciousApp",
            "Value": "C:\\Windows\\Temp\\malware.exe",
            "Path": "C:\\Windows\\Temp\\malware.exe",
            "Code": "RUN03",
            "Context": "The SuspiciousApp App Is Running From A Temporary Directory Could Be Malicious."
        }
    ],
    "Not Valid Service": [
        {
            "Name": "BadService",
            "Results": {
                "Path": "C:\\Temp\\badservice.exe",
                "Status": "NotSigned"
            },
            "Code": "S01",
            "Context": "After Checking For The Sign Of The Service It Turns Out It Was Not Valid."
        }
    ]
}
```

## How It Works

1. **Registry Parsing**: Uses the `Registry` library to parse the provided registry hive file.
2. **Auto-Run Checks**: Scans `Run` and `RunOnce` keys for suspicious entries, checking for temporary paths and random names using frequency analysis.
3. **Service Validation**: Verifies services under `CurrentControlSet\Services` for valid signatures and standard paths, with VirusTotal hash checks.
4. **Winlogon, AppInit, UAC, and More**: Validates critical registry keys against default values and flags deviations.
5. **Firewall and Defender**: Checks for disabled firewall or Defender settings.
6. **Output Generation**: Writes findings to `alarms.json` and, if specified, service signatures to `signs.json`.

## Limitations

- **Windows Dependency**: The tool relies on PowerShell for file hash and signature checks, making it Windows-specific.
- **VirusTotal API**: Requires a valid API key and internet access for hash checks.
- **Registry Hive**: Requires a valid registry hive file (e.g., `SYSTEM`, `SOFTWARE`).
- **Frequency Analysis**: Depends on the `freqtable2018.freq` file for random name detection.

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m "Add your feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a Pull Request.

Please ensure your code follows PEP 8 guidelines and includes appropriate tests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For questions or issues, please open an issue on the GitHub repository or contact the maintainer at `<your-email>`.

---

*Built with security in mind, for a safer Windows environment.*