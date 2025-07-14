
# JWT Security Assessment Dashboard

A comprehensive, static web application for JWT (JSON Web Token) security assessment and penetration testing. This dashboard provides real-world attack vectors, vulnerability analysis, and professional security testing tools for JWT implementations.

## Features

### JWT Token Analyzer
- Real-time JWT token parsing and analysis
- Automatic vulnerability detection and alerts
- Security misconfiguration identification
- Header, payload, and signature inspection

### Attack Vectors
- **None Algorithm Attack** (CVE-2015-9235): Bypass signature verification
- **Algorithm Confusion** (CVE-2016-10555): RS256 to HS256 conversion attacks
- **Brute Force Attack** (CVE-2020-28637): Dictionary attacks against weak secrets
- **Timing Attack** (CVE-2019-20933): Exploit timing differences in verification
- **JWS Signature Bypass** (CVE-2022-21449): Psychic signatures exploitation
- **JKU Header Injection** (CVE-2018-0114): Malicious key URL manipulation
- **Kid Header Injection** (CVE-2021-29923): Path traversal via Key ID
- **Null Byte Injection** (CVE-2019-7644): C/C++ implementation bypass
- **JWT Bomb** (CVE-2021-31684): Memory exhaustion attacks
- **JWKS Confusion** (CVE-2022-29217): Key confusion exploitation
- **Header Manipulation** (CVE-2020-8116): Parser confusion attacks
- **Infinite Loop** (CVE-2021-35065): Recursive structure exploitation

### Misconfiguration Detection
- No signature verification detection
- Hardcoded secret identification
- Missing expiration checks
- Weak algorithm usage analysis

### Penetration Testing Tools
- JWT encoder/decoder with custom payloads
- Signature verification testing
- Unix timestamp converter
- Wordlist generator for brute force attacks

## Technical Stack

- **Frontend**: Pure HTML5, CSS3, JavaScript (ES6+)
- **Fonts**: Inter, JetBrains Mono
- **Icons**: Font Awesome 6.0
- **Architecture**: Static web application, no backend dependencies
- **Compatibility**: Modern browsers with ES6+ support

## Installation

1. Clone the repository:
```bash
git clone https://github.com/0x0806/jwt-security-dashboard.git
cd jwt-security-dashboard
```

2. Serve the files using any static web server:
```bash
# Using Python
python -m http.server 8000

# Using Node.js
npx http-server

# Using PHP
php -S localhost:8000
```

3. Open your browser and navigate to `http://localhost:8000`

## Usage

### Basic JWT Analysis
1. Navigate to the "JWT Analyzer" tab
2. Paste your JWT token into the input field
3. Click "Analyze Token" to view decoded components
4. Review security alerts and vulnerability warnings

### Attack Vector Testing
1. Switch to the "Attack Vectors" tab
2. Browse through available attack demonstrations
3. Click "Demonstrate Attack" buttons for proof-of-concept examples
4. Study CVE references and attack methodologies

### Security Assessment
1. Use the "Misconfigurations" tab to understand common JWT implementation flaws
2. Access "Pentest Tools" for practical security testing utilities
3. Generate custom JWT tokens for testing
4. Verify signatures and analyze timestamps

## Security Considerations

This tool is designed for:
- Educational purposes and security research
- Authorized penetration testing engagements
- Security awareness training
- Vulnerability assessment of JWT implementations

**Important**: Only use this tool against systems you own or have explicit permission to test. Unauthorized security testing may violate laws and regulations.

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-attack`)
3. Commit your changes (`git commit -am 'Add new attack vector'`)
4. Push to the branch (`git push origin feature/new-attack`)
5. Create a Pull Request

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The developer assumes no responsibility for any misuse or damage caused by this software. Users must ensure they have proper authorization before testing any systems.

## CVE References

This dashboard includes demonstrations and analysis for the following CVEs:
- CVE-2015-9235, CVE-2016-10555, CVE-2020-28637, CVE-2019-20933
- CVE-2022-21449, CVE-2018-0114, CVE-2021-29923, CVE-2019-7644
- CVE-2021-31684, CVE-2022-29217, CVE-2020-8116, CVE-2021-35065

## Author

Developed by **0x0806**

- GitHub: [github.com/0x0806](https://github.com/0x0806)
- Project Repository: [github.com/0x0806/jwt-security-dashboard](https://github.com/0x0806/jwt-security-dashboard)

## Support

For questions, issues, or feature requests, please create an issue on the GitHub repository.
