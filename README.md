
# JWT Security Assessment Dashboard

A comprehensive, static web application for JWT (JSON Web Token) security assessment and penetration testing. This dashboard provides real-world attack vectors, vulnerability analysis, and professional security testing tools for JWT implementations.

## Features

### JWT Token Analyzer
- Real-time JWT token parsing and analysis
- Automatic vulnerability detection and alerts
- Security misconfiguration identification
- Header, payload, and signature inspection

### Attack Vectors
34 catalogued vectors — filterable by severity or free-text search in the UI. 21 cite a specific, verified CVE; 13 are documented techniques that don't map to one single CVE (marked "No single CVE" rather than guessing a number). Each card expands into proof-of-concept notes and the affected target/version range. Highlights:

- **None Algorithm Attack** (CVE-2015-9235), **RS256→HS256 Algorithm Confusion** (CVE-2016-10555), **Psychic Signatures / ECDSA r=0,s=0** (CVE-2022-21449), **JWKS Key-Type Confusion** (CVE-2022-29217)
- **jsonwebtoken (npm)** trio — "none" accepted by default (CVE-2022-23540), legacy key types (CVE-2022-23539), asymmetric key verified as HS256 (CVE-2022-23541)
- **json-web-token** alg-read-before-verify (CVE-2023-48238), **fast-jwt** algorithm confusion (CVE-2023-48223) and issuer-array confusion (CVE-2025-30144)
- **PyJWT** issuer validation bug (CVE-2024-53861) and JWK algorithm-confusion bypass (CVE-2026-48526)
- **libjwt** non-constant-time signature comparison (CVE-2024-25189, CVSS 9.8), **go-jose** memory exhaustion (CVE-2025-27144)
- **JJWT** weak-key character handling — disputed by vendor (CVE-2024-31033), **lcobucci/jwt** wrong hash via file-loaded key (CVE-2021-41106)
- **Auth0-WCF-Service-JWT** signature value disclosed in error messages (CVE-2019-7644)
- **Keycloak** trio — JWT grant algorithm confusion (CVE-2026-11800), unsigned assertion bypass (CVE-2026-16093), disabled users still granted JWTs (CVE-2026-1609)
- **jose (panva)** JWE decompression resource exhaustion (CVE-2024-28176) — corrected from an earlier version of this catalog that mis-described this as RCE in the unrelated `node-jose` package
- Technique-only entries without a specific CVE: brute force, timing attacks, jku/kid header injection, null byte injection, claim/zip bombs, header-parameter abuse, infinite loops, JWKS cache poisoning, Go "none" downgrade, lightweight-library DoS, PASETO footer manipulation

See the in-app notes on each card for sourcing caveats (a couple of entries carry a vendor dispute or limited public detail) — always re-verify against NVD/vendor advisories before citing one in a report.

### Misconfiguration Detection
- No signature verification detection
- Hardcoded secret identification
- Missing expiration checks
- Weak algorithm usage analysis
- Algorithm not pinned (confusion risk)
- Sensitive data exposed in the payload
- Missing audience/issuer validation

### Penetration Testing Tools
All signing/verification tools use the browser's Web Crypto API (real HMAC), not a simulated signature.

- **JWT Encoder** — build and sign a token with HS256/384/512, or leave it unsigned (`alg: none`)
- **Signature Verifier** — recompute the HMAC for a candidate secret and check it against a token
- **Secret Brute-Forcer** — dictionary attack an HS256/384/512 token in-browser, built-in common-secrets list or your own wordlist
- **Claim Forge** — load a token's header/payload into an editor, tamper with claims, and re-sign (resign with a secret, strip to `alg: none`, or algorithm-confusion mode using a pasted key as the HMAC secret)
- **JWKS Inspector** — fetch a JWKS endpoint and flag duplicate `kid`s or exposed symmetric (`oct`) keys
- **Unix timestamp converter**
- **Wordlist generator** — common/numeric/alphanumeric secret lists, exportable as `.txt` for Burp Intruder or hashcat

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

**Historical CVEs (2015-2022):**
- CVE-2015-9235, CVE-2016-10555, CVE-2020-28637, CVE-2019-20933
- CVE-2022-21449, CVE-2018-0114, CVE-2021-29923, CVE-2019-7644
- CVE-2021-31684, CVE-2022-29217, CVE-2020-8116, CVE-2021-35065

**Latest 2024 CVEs:**
- CVE-2024-51498, CVE-2024-28176, CVE-2024-28851, CVE-2024-25710
- CVE-2024-33883, CVE-2024-45234

## Author

Developed by **0x0806**

- GitHub: [github.com/0x0806](https://github.com/0x0806)
- Project Repository: [github.com/0x0806/jwt-security-dashboard](https://github.com/0x0806/jwt-security-dashboard)

## Support

For questions, issues, or feature requests, please create an issue on the GitHub repository.
