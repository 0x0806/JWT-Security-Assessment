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
            btn.addEventListener('click', (e) => this.switchTab(e.currentTarget.dataset.tab));
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

            // Mirror the live token into the header's segment readout
            this.updateTokenStrip(parts[0], parts[1], signature);

            // Perform security analysis
            this.performSecurityAnalysis(JSON.parse(header), JSON.parse(payload), signature);

        } catch (error) {
            this.showAlert('Error parsing JWT: ' + error.message, 'critical');
        }
    }

    updateTokenStrip(headerPart, payloadPart, signaturePart) {
        const truncate = (str, max) => (str && str.length > max ? str.slice(0, max) + '…' : str);
        const headerEl = document.getElementById('strip-header');
        const payloadEl = document.getElementById('strip-payload');
        const signatureEl = document.getElementById('strip-signature');
        if (headerEl) headerEl.textContent = truncate(headerPart, 24);
        if (payloadEl) payloadEl.textContent = truncate(payloadPart, 24);
        if (signatureEl) signatureEl.textContent = truncate(signaturePart, 24) || '(unsigned)';
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

// ===== Attack vector catalog =====
// Each entry is either a real, verified CVE (verified against public advisories/NVD
// at the time this catalog was written — always re-check before citing in a report)
// or a documented technique that doesn't map to one specific CVE, marked `cve: null`.
// A few entries from an earlier version of this catalog cited CVE numbers that don't
// match their description (e.g. an unrelated Go stdlib CVE, or a DoS mis-described as
// RCE); those have been corrected here rather than carried forward.

const ATTACK_VECTORS = [
    {
        id: 'none-alg', icon: 'fa-key', title: 'None Algorithm Attack', severity: 'critical',
        cve: 'CVE-2015-9235', target: 'ruby-jwt < 1.5.1 and other early JWT libraries',
        summary: 'Exploit JWT tokens that accept "none" algorithm, bypassing signature verification entirely.',
        demoLabel: 'Vulnerable token', demoCode: 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.',
        details: ['A token is crafted with header {"alg":"none"} and an empty signature segment.', 'A library that treats "none" as a valid, checkable algorithm accepts it without verifying anything.', 'The payload (here admin: true) is trusted as-is.'],
        impact: 'Complete authentication bypass — any claim in the payload is accepted unverified.'
    },
    {
        id: 'alg-confusion', icon: 'fa-exchange-alt', title: 'RS256→HS256 Algorithm Confusion', severity: 'high',
        cve: 'CVE-2016-10555', target: 'node-jsonwebtoken, pyjwt and other libraries that shared one verify path for both algorithm families',
        summary: 'Convert RS256 tokens to HS256 using the server\'s own RSA public key as the HMAC secret.',
        demoLabel: 'Attack vector', demoCode: 'HS256(payload, rsaPublicKeyPEM) → signature the server treats as valid',
        details: ['Obtain the RS256 public key (often published at a JWKS endpoint).', 'Build a new token with header alg: HS256, keeping the same claims.', 'Sign it with HMAC-SHA256 using the PEM public key text as the secret.', 'A verify() call that does not pin the expected algorithm will use the same public key as an HMAC secret and accept the forged signature.'],
        impact: 'Full authentication bypass — the attacker signs arbitrary tokens the server will trust.'
    },
    {
        id: 'brute-force', icon: 'fa-hammer', title: 'Weak-Secret Brute Force', severity: 'medium', cve: null,
        target: 'Any HS256/384/512 implementation using a short or dictionary-word secret',
        summary: 'Dictionary and brute-force attacks against weak HMAC secrets.',
        demoLabel: 'Common weak secrets', demoList: ['secret', 'password', 'admin', '123456', 'jwt_secret', 'your-256-bit-secret'],
        details: ['Not a single CVE — a configuration weakness in how a specific deployment chose its signing secret.', 'An attacker recomputes HMAC(header.payload, candidate) for each wordlist entry and compares it to the token\'s signature.', 'Use the Secret Brute-Forcer in the Pentest Tools tab to run this for real against a token.'],
        impact: 'Token forgery and full privilege escalation once the secret is recovered.'
    },
    {
        id: 'timing', icon: 'fa-clock', title: 'Signature Comparison Timing Attack', severity: 'medium', cve: null,
        target: 'Implementations that compare signatures with a non-constant-time equality check',
        summary: 'Exploit timing differences in JWT signature verification to recover secret bytes.',
        demoLabel: 'Technique', demoCode: 'Measure response time while comparing signature bytes one at a time',
        details: ['If signature comparison short-circuits on the first mismatched byte, a correct prefix takes measurably longer to reject.', 'Repeating this per byte position can recover the expected signature without knowing the secret.', 'See CVE-2024-25189 below for a concrete, confirmed instance of this class in libjwt.'],
        impact: 'Signature or secret recovery, enabling token forgery.'
    },
    {
        id: 'psychic-sig', icon: 'fa-bug', title: 'Psychic Signatures (ECDSA)', severity: 'critical',
        cve: 'CVE-2022-21449', target: 'Java 15, 16, 17, 18 (java.security.Signature for ECDSA)',
        summary: 'Java\'s ECDSA signature verification accepted invalid signatures where both r and s are zero.',
        demoLabel: 'Psychic signature', demoCode: '{"r": "AAAA...", "s": "AAAA..."} → treated as valid for ANY message',
        details: ['A legacy ASN.1 parsing bug let a signature encoding (r=0, s=0) pass verification for any message or key.', 'Any ES256/ES384/ES512-signed JWT could be forged by substituting this all-zero signature.', 'Fixed in the April 2022 Java CPU; patch to a non-vulnerable JDK build.'],
        impact: 'Complete signature bypass for any ECDSA-based JWT on an unpatched JVM.'
    },
    {
        id: 'jku', icon: 'fa-link', title: 'jku Header Injection', severity: 'high', cve: null,
        target: 'Any verifier that fetches jku without an allowlist',
        summary: 'Point the jku (JWK Set URL) header at an attacker-controlled JWKS endpoint.',
        demoLabel: 'Malicious header', demoCode: '{"alg": "RS256", "jku": "https://attacker.example/jwks.json"}',
        details: ['Host a JWKS document containing an attacker-generated RSA keypair.', 'Sign a forged token with the matching private key and set jku to the attacker\'s URL.', 'A verifier that blindly fetches whatever URL jku names will validate the forged signature against the attacker\'s own public key.'],
        impact: 'Authentication bypass — always pin jku to an allowlisted host, never follow it blindly.'
    },
    {
        id: 'kid-traversal', icon: 'fa-fingerprint', title: 'kid Header Path Traversal', severity: 'high', cve: null,
        target: 'Verifiers that build a filesystem path directly from the kid header',
        summary: 'Exploit the kid (Key ID) header for path traversal and predictable-file key confusion.',
        demoLabel: 'Path traversal', demoCode: '{"kid": "../../../../dev/null"}',
        details: ['If kid is concatenated into a file path to load the verification key, traversal sequences can redirect it to a known file.', '/dev/null resolves to an empty key — the attacker signs with HMAC of an empty secret and the server reads the same empty "key".', 'This is a well-documented technique (see PortSwigger\'s JWT labs) rather than one specific CVE — the fix is to validate kid against an allowlist, never a raw path.'],
        impact: 'Authentication bypass and potential arbitrary file disclosure via the signature oracle.'
    },
    {
        id: 'sig-disclosure', icon: 'fa-exclamation-circle', title: 'Signature Value Disclosed in Error Message', severity: 'critical',
        cve: 'CVE-2019-7644', target: 'Auth0-WCF-Service-JWT (NuGet) < 1.0.4',
        summary: 'On a failed verification, the library\'s error response revealed the signature value it expected.',
        demoLabel: 'Vulnerable response', demoCode: '{"error": "invalid signature", "expected": "<leaked-signature-bytes>"}',
        details: ['An attacker sends a token with a guessed or empty signature and reads the expected value back from the error output.', 'Repeating this exposes enough of the expected signature to construct a token the server will accept.', 'CVSS 9.8 (Critical) — CWE-209, information exposure through an error message.'],
        impact: 'Full signature forgery without ever learning the signing secret.'
    },
    {
        id: 'jwt-bomb', icon: 'fa-shield-alt', title: 'JWT Claim-Bomb DoS', severity: 'high', cve: null,
        target: 'Parsers without depth/size limits on the decoded payload',
        summary: 'Craft a token whose JSON payload is deeply nested or holds huge repeated arrays, to exhaust memory on parse.',
        demoLabel: 'Memory exhaustion', demoCode: 'Deeply nested objects + large repeated arrays in the payload claims',
        details: ['A payload nested hundreds of levels deep, or containing very large arrays/strings, costs disproportionate CPU/memory to parse and re-serialize.', 'This is a generic JSON-parser risk, not tied to one JWT CVE — libraries that cap payload size or nesting depth are not affected.'],
        impact: 'Denial of service on the verifying service.'
    },
    {
        id: 'jwks-confusion', icon: 'fa-random', title: 'JWKS Key-Type Confusion', severity: 'critical',
        cve: 'CVE-2022-29217', target: 'PyJWT (and similar) when an app accepts every algorithm PyJWT supports',
        summary: 'An app that calls get_default_algorithms() accepts both symmetric and asymmetric algorithms from one verify() call.',
        demoLabel: 'Key confusion', demoCode: 'RSA public key supplied where an HMAC secret was expected',
        details: ['If verify() is given every supported algorithm instead of the one the app actually issues, an RS256 public key can be re-used as the HS256 secret.', 'Fixed in PyJWT 2.4.0 by rejecting PEM/SSH-formatted keys as HMAC secrets — see CVE-2026-48526 below for the bypass of that fix.'],
        impact: 'Authentication bypass via algorithm/key confusion.'
    },
    {
        id: 'header-manip', icon: 'fa-compress', title: 'Header Parameter Abuse (cty/zip/crit/x5u)', severity: 'medium', cve: null,
        target: 'Verifiers that honor optional JWS header parameters without restriction',
        summary: 'Use optional header parameters to confuse the parser or redirect key resolution.',
        demoLabel: 'Header injection', demoCode: '{"alg":"HS256","zip":"DEF","crit":["alg"],"x5u":"https://attacker.example/cert.pem"}',
        details: ['zip can request payload decompression — a deflate bomb here is a smaller cousin of the claim-bomb DoS above.', 'crit lets a token declare a header parameter as mandatory; some parsers mishandle unknown critical parameters.', 'x5u works like jku but for X.509 certificate chains — same blind-fetch risk if not allowlisted.'],
        impact: 'Parser confusion, validation bypass, or DoS depending on which parameter is abused.'
    },
    {
        id: 'infinite-loop', icon: 'fa-infinity', title: 'Circular-Reference Parser DoS', severity: 'medium', cve: null,
        target: 'JSON parsers/serializers without cycle detection',
        summary: 'Craft a payload structure that causes a parser to loop while resolving self-references.',
        demoLabel: 'Recursive structure', demoCode: '{"user":{"profile":{"parent":"$.user"}}}',
        details: ['Standard JSON has no native circular references, but custom deserializers that resolve path-like claims (e.g. "$.user") can be tricked into looping.', 'This is an implementation-specific risk in custom claim-resolution code, not standard JWT parsing.'],
        impact: 'Denial of service if the server becomes unresponsive while looping.'
    },
    {
        id: 'null-byte', icon: 'fa-skull', title: 'Null Byte Injection', severity: 'high', cve: null,
        target: 'C/C++-backed JWT parsers that treat strings as null-terminated',
        summary: 'Embed a null byte in a header value so a null-terminated-string parser reads a different value than a length-aware one does.',
        demoLabel: 'Payload with a null byte', demoCode: '{"alg": "none\\u0000HS256"}',
        details: ['A C/C++ component that treats strings as null-terminated will stop reading at \\x00, while the JSON layer above it sees the full string.', 'That mismatch can smuggle a different alg, kid, or jku value past a validation check than the one actually used downstream.', 'Not tied to one CVE here — it is a parser-mismatch class that shows up differently in each affected codebase.'],
        impact: 'Validation bypass or injection, depending on which header field is truncated and how it is used afterward.'
    },
    {
        id: 'go-none-accept', icon: 'fa-lock-open', title: 'Go JWT Library: HMAC-to-none Downgrade', severity: 'high', cve: null,
        target: 'Go JWT libraries/applications that don\'t pin the expected algorithm in Parse()',
        summary: 'A server expecting HMAC-signed tokens incorrectly accepts a token whose header declares "none".',
        demoLabel: 'Algorithm downgrade', demoCode: 'jwt.Parse(tokenString, keyFunc) // keyFunc never checks token.Method before returning the key',
        details: ['This is the Go-ecosystem instance of the general "none" algorithm class (see the first card above) — the fix is identical: assert the expected signing method inside keyFunc before returning a key.', 'No single CVE number is cited here; check your specific Go JWT library\'s advisories for a version-specific fix.'],
        impact: 'Complete authentication bypass for any application relying on the library\'s default behavior.'
    },
    {
        id: 'jwt-simple-dos', icon: 'fa-shield-virus', title: 'Malformed-Token DoS in Lightweight Libraries', severity: 'high', cve: null,
        target: 'Minimal JWT libraries without input-size limits (e.g. older jwt-simple-style packages)',
        summary: 'Send oversized or malformed tokens to a parser that does no size-checking before processing.',
        demoLabel: 'DoS vector', demoCode: "'eyJhbGciOiJIUzI1NiJ9.' + 'A'.repeat(100000) + '.sig'",
        details: ['A minimal library focused on happy-path parsing often skips bounds checks a production-grade one would have.', 'Repeated requests with multi-megabyte tokens can exhaust CPU or memory before a WAF or reverse proxy would normally intervene.'],
        impact: 'Denial of service against the parsing service.'
    },
    {
        id: 'paseto-footer', icon: 'fa-user-secret', title: 'PASETO Footer Manipulation', severity: 'medium', cve: null,
        target: 'PASETO implementations with permissive footer handling',
        summary: 'PASETO (an alternative to JWT) carries an optional, unencrypted footer — implementations that parse it loosely can be confused by crafted footer content.',
        demoLabel: 'Technique', demoCode: 'v2.public.<payload>.<attacker-controlled footer>',
        details: ['PASETO is a different token format from JWT, designed specifically to avoid the "alg" confusion class above — but its footer field is still implementation-defined and worth testing on any PASETO-issuing target.', 'Treat this as a reminder to test footer handling explicitly, not as a confirmed vulnerability in any specific library.'],
        impact: 'Varies by implementation — ranges from information disclosure to validation bypass if the footer is trusted unsafely.'
    },
    {
        id: 'jwt-zip-bomb-v2', icon: 'fa-compress-arrows-alt', title: 'Nested-Compression Claim Bomb', severity: 'medium', cve: null,
        target: 'Parsers that support the zip (compression) header parameter with no expansion-ratio limit',
        summary: 'A variant of the claim-bomb DoS above, using layered compression so a small token expands enormously on decompression.',
        demoLabel: 'Recursive bomb', demoCode: 'zip: "DEF" header + a payload engineered for a very high compression ratio',
        details: ['Each additional compression layer multiplies the eventual decompressed size — a classic "zip bomb" shape applied to the zip JWT header parameter.', 'Mitigation is the same as any decompression bomb: cap the decompressed size before trusting it, not just the compressed size.'],
        impact: 'Severe denial of service from a very small request.'
    },
    {
        id: 'jwks-cache-poisoning', icon: 'fa-network-wired', title: 'JWKS Cache Poisoning', severity: 'medium', cve: null,
        target: 'JWKS consumers that cache responses based on attacker-influenced cache headers',
        summary: 'If a JWKS response can be influenced (via CDN cache-key confusion, a compromised intermediary, or an open cache) its keys can be cached and served to every subsequent verifier.',
        demoLabel: 'Cache poisoning', demoCode: 'Cache-Control: public, max-age=31536000 on a malicious JWKS response',
        details: ['A long max-age turns a one-time key substitution into a long-lived, hard-to-detect compromise.', 'Defend by validating JWKS over a pinned, authenticated channel and keeping cache lifetimes short enough to bound the damage of a bad entry.'],
        impact: 'Persistent authentication bypass for every client that reads the poisoned cache entry.'
    },
    {
        id: 'jsonwebtoken-none-default', icon: 'fa-unlock', title: 'jsonwebtoken: "none" Accepted by Default', severity: 'high',
        cve: 'CVE-2022-23540', target: 'jsonwebtoken (npm, Auth0) < 9.0.0',
        summary: 'jwt.verify() silently defaulted to allowing the "none" algorithm when the caller did not pass an explicit algorithms list.',
        demoLabel: 'Vulnerable call', demoCode: "jwt.verify(token, key) // no { algorithms: [...] } passed",
        details: ['Any caller that relied on jwt.verify()\'s defaults — rather than stating algorithms explicitly — accepted unsigned tokens.', 'Fixed in 9.0.0, which removed the implicit "none" default; it must now be opted into explicitly.'],
        impact: 'Signature validation bypass on any integration using the old default.'
    },
    {
        id: 'jsonwebtoken-legacy-keys', icon: 'fa-id-badge', title: 'jsonwebtoken: Legacy Key Types Accepted', severity: 'high',
        cve: 'CVE-2022-23539', target: 'jsonwebtoken (npm, Auth0) < 9.0.0',
        summary: 'Misconfiguration let legacy, weaker key types (e.g. DSA) be used for signature verification in place of the intended algorithm.',
        demoLabel: 'Vulnerable combination', demoCode: 'DSA key accepted where RS256 was expected',
        details: ['9.0.0 requires explicit allowInvalidAsymmetricKeyTypes to accept a key/algorithm combination the library considers invalid.'],
        impact: 'Weaker cryptography accepted silently, widening the attack surface for key recovery.'
    },
    {
        id: 'jsonwebtoken-pubkey-as-hmac', icon: 'fa-exchange-alt', title: 'jsonwebtoken: Asymmetric Key Verified as HS256', severity: 'critical',
        cve: 'CVE-2022-23541', target: 'jsonwebtoken (npm, Auth0) < 9.0.0',
        summary: 'A token signed with an asymmetric public key could be verified using the symmetric HS256 algorithm, succeeding on a forged token.',
        demoLabel: 'Vulnerable call', demoCode: 'jwt.verify(forgedToken, rsaPublicKeyAsString) // HS256 path accepted it',
        details: ['This is the library-specific instance of the general RS256→HS256 confusion class (see CVE-2016-10555 above).', 'Fixed in 9.0.0 alongside CVE-2022-23539 and CVE-2022-23540.'],
        impact: 'Full authentication bypass via forged HS256 tokens.'
    },
    {
        id: 'json-web-token-alg-confusion', icon: 'fa-code', title: 'json-web-token: alg Read Before Verification', severity: 'high',
        cve: 'CVE-2023-48238', target: 'json-web-token (npm, joaquimserafim) < 3.1.1 — not the same package as jsonwebtoken',
        summary: 'The library read the alg value from the still-unverified token before deciding how to check its signature.',
        demoLabel: 'Vulnerable flow', demoCode: 'decode(token).header.alg // trusted before the signature is checked',
        details: ['Trusting attacker-controlled header fields before verification is the root cause behind most algorithm-confusion bugs.', 'Exploitable specifically where the application uses RS256. CVSS 7.5 (High), CWE-345.'],
        impact: 'Signature verification bypass on RS256 deployments of this package.'
    },
    {
        id: 'fast-jwt-alg-confusion', icon: 'fa-bolt', title: 'fast-jwt: Algorithm Confusion Across Key Types', severity: 'high',
        cve: 'CVE-2023-48223', target: 'fast-jwt (npm) < 3.3.2',
        summary: 'fast-jwt did not fully prevent algorithm confusion across all supported public-key types.',
        demoLabel: 'Technique', demoCode: 'Public key of one algorithm family reused as the verification secret for another',
        details: ['Same root cause as CVE-2016-10555, in a different, actively-maintained library.', 'Upgrade to 3.3.2 or later, and always pin the expected algorithm.'],
        impact: 'Authentication bypass via algorithm confusion.'
    },
    {
        id: 'fast-jwt-iss-array', icon: 'fa-list-ul', title: 'fast-jwt: Issuer Array Confusion', severity: 'medium',
        cve: 'CVE-2025-30144', target: 'fast-jwt (npm), fixed in later releases',
        summary: 'The library accepted an array of strings as a valid iss claim, letting a token list both a legitimate and a malicious issuer together.',
        demoLabel: 'Vulnerable payload', demoCode: '{"iss": ["https://trusted.example", "https://attacker.example"]}',
        details: ['An iss allowlist check that expects a single string can be satisfied by an array containing the expected value alongside an attacker-chosen one.', 'Downstream code that then trusts "the issuer" without re-checking which array entry matched is exposed to issuer confusion.'],
        impact: 'Cross-issuer trust confusion, potentially enabling token replay across tenants.'
    },
    {
        id: 'pyjwt-iss-validation', icon: 'fa-passport', title: 'PyJWT: Issuer Claim Validation Bug', severity: 'medium',
        cve: 'CVE-2024-53861', target: 'PyJWT 2.10.0, fixed in 2.10.1',
        summary: 'A regression in issuer-claim handling weakened the iss validation added in that release.',
        demoLabel: 'Technique', demoCode: 'decode(token, issuer="https://expected.example") // validation bypassed under specific conditions',
        details: ['Introduced in 2.10.0 and fixed one patch release later — a reminder to pin exact dependency versions and track security advisories, not just major versions.'],
        impact: 'Tokens from an unintended issuer could pass validation.'
    },
    {
        id: 'pyjwt-jwk-confusion', icon: 'fa-key', title: 'PyJWT: JWK Algorithm-Confusion Bypass', severity: 'high',
        cve: 'CVE-2026-48526', target: 'PyJWT 2.4.0–2.10.1 (the original CVE-2022-29217 fix was incomplete)',
        summary: 'When an app accepts both symmetric and asymmetric algorithms and passes a raw JWK string, that JWK can be reused as an HMAC secret.',
        demoLabel: 'Technique', demoCode: 'HS256(signingInput, rawPublicJWKString) // accepted by the vulnerable range',
        details: ['The 2022 fix blocked PEM/SSH-formatted public keys from being used as HMAC secrets, but not raw JWK-string input.', 'CVSS 7.4. Mitigate by never mixing symmetric and asymmetric algorithm families in one decode() call, and by parsing keys with PyJWK instead of passing raw JSON.'],
        impact: 'Authentication bypass via algorithm/key confusion, bypassing the earlier published fix.'
    },
    {
        id: 'libjwt-timing', icon: 'fa-stopwatch', title: 'libjwt: Non-Constant-Time Signature Comparison', severity: 'critical',
        cve: 'CVE-2024-25189', target: 'libjwt (C) 1.15.3',
        summary: 'libjwt used strcmp — which is not constant-time — to compare signatures during verification.',
        demoLabel: 'Vulnerable comparison', demoCode: 'strcmp(expectedSignature, providedSignature) // early-exits on first mismatch',
        details: ['strcmp returns as soon as it finds a differing byte, so comparison time leaks how many leading bytes matched.', 'A remote attacker measuring response time can recover the signature byte by byte.', 'CVSS 9.8 (Critical). The fix is a constant-time comparison function.'],
        impact: 'Signature recovery via timing side channel, enabling full token forgery.'
    },
    {
        id: 'go-jose-dos', icon: 'fa-wind', title: 'go-jose: Malformed-Token Memory Exhaustion', severity: 'medium',
        cve: 'CVE-2025-27144', target: 'go-jose (Go)',
        summary: 'Specially malformed tokens caused excessive memory use while being parsed.',
        demoLabel: 'Technique', demoCode: 'Malformed JOSE structure → disproportionate allocation during parse',
        details: ['A denial-of-service class issue (CWE-400, uncontrolled resource consumption), not a signature bypass.', 'Update to a patched go-jose release and consider request-size limits in front of the parser.'],
        impact: 'Denial of service against services using the affected go-jose versions.'
    },
    {
        id: 'jjwt-weak-key', icon: 'fa-eye-slash', title: 'JJWT: Signing-Key Character Handling', severity: 'medium',
        cve: 'CVE-2024-31033', disputed: true, target: 'JJWT / io.jsonwebtoken (Java) ≤ 0.12.5',
        summary: 'JJWT ignored certain characters when deriving a key, so a developer could believe a key was stronger than it actually was.',
        demoLabel: 'Technique', demoCode: 'A key string with ignored characters effectively has less entropy than it looks like it has',
        details: ['The vendor disputes this report, saying it requires a specific misuse pattern rather than a library defect on its own.', 'Listed here for completeness — note the dispute before citing it in a report.'],
        impact: 'Weaker effective key strength than intended, if the disputed misuse pattern applies.'
    },
    {
        id: 'lcobucci-file-key', icon: 'fa-file-signature', title: 'lcobucci/jwt: Wrong Hash via File-Loaded Key', severity: 'medium',
        cve: 'CVE-2021-41106', target: 'lcobucci/jwt (PHP) — fixed in 3.4.6, 4.0.4, 4.1.5',
        summary: 'HMAC-based tokens could be produced with an incorrect hash when the signing key was loaded via a file-reference key object.',
        demoLabel: 'Vulnerable usage', demoCode: 'Lcobucci\\JWT\\Signer\\Key\\LocalFileReference::file(\'path/to/key\')',
        details: ['Switching to the InMemory key class instead of LocalFileReference avoids the flaw.', 'CVSS 4.4 (Medium).'],
        impact: 'Tokens signed with a weaker-than-intended hash, undermining the HMAC\'s integrity guarantee.'
    },
    {
        id: 'keycloak-jwt-grant-confusion', icon: 'fa-building-shield', title: 'Keycloak: Algorithm Confusion in JWT Authorization Grant', severity: 'high',
        cve: 'CVE-2026-11800', target: 'Keycloak < 26.6.4',
        summary: 'An attacker holding valid client credentials could bypass signature verification in the JWT Authorization Grant flow via algorithm confusion.',
        demoLabel: 'Technique', demoCode: 'Client-credential holder swaps the expected signing algorithm during the grant exchange',
        details: ['CVSS 8.1 (High).', 'Fixed in Keycloak 26.6.4 — upgrade and review which clients are permitted to use this grant type.'],
        impact: 'Authentication bypass for clients that already hold valid credentials, escalating their effective trust.'
    },
    {
        id: 'keycloak-unsigned-assertion', icon: 'fa-file-circle-exclamation', title: 'Keycloak: Unsigned JWT Assertion Accepted', severity: 'high',
        cve: 'CVE-2026-16093', target: 'Keycloak (Client Policies feature)',
        summary: 'An attacker with valid client credentials could bypass the signed-JWT-assertion requirement enforced by Client Policies.',
        demoLabel: 'Technique', demoCode: 'Submit an unsigned (or improperly signed) client assertion where a signed one is policy-required',
        details: ['Defeats a Client Policy specifically meant to require cryptographic proof of client identity.'],
        impact: 'Bypasses an intended client-authentication control, not just a weak default.'
    },
    {
        id: 'keycloak-disabled-user-grant', icon: 'fa-user-slash', title: 'Keycloak: Disabled Users Still Obtain JWTs', severity: 'medium',
        cve: 'CVE-2026-1609', target: 'Keycloak < 26.5.3 (JWT Authorization Grant preview feature)',
        summary: 'Disabled user accounts could still obtain JWT tokens through external identity providers via the preview JWT Authorization Grant feature.',
        demoLabel: 'Technique', demoCode: 'Disabled account authenticates via an external IdP, still receives a usable JWT',
        details: ['Improper access control (the disabled-account check was bypassed for this specific flow).', 'Fixed in Keycloak 26.5.3.'],
        impact: 'Account disablement does not actually revoke access — a serious gap for incident response and offboarding.'
    },
    {
        id: 'jose-decompression-dos', icon: 'fa-file-zipper', title: 'jose: JWE Decompression Resource Exhaustion', severity: 'medium',
        cve: 'CVE-2024-28176', target: 'jose (npm, panva) — not the separate node-jose package',
        summary: 'Decrypting a JWE with plaintext decompression enabled could drive CPU/memory use disproportionately high.',
        demoLabel: 'Technique', demoCode: 'A small, crafted JWE ciphertext that decompresses to a very large plaintext',
        details: ['This is a denial-of-service issue (CWE-400), not remote code execution — an earlier version of this catalog mis-described it as RCE in the unrelated node-jose package; that was incorrect and has been fixed here.', 'CVSS 4.9 (Medium). Fixed in 2.0.7 and 4.15.5.'],
        impact: 'Resource exhaustion on services that decrypt attacker-supplied JWEs with compression enabled.'
    }
];

function severityRank(sev) {
    return { critical: 0, high: 1, medium: 2 }[sev] ?? 3;
}

function renderAttackVectors(filterText = '', filterSeverity = 'all') {
    const grid = document.getElementById('attack-grid');
    const empty = document.getElementById('attack-empty');
    const summary = document.getElementById('attack-summary');
    if (!grid) return;

    const needle = filterText.trim().toLowerCase();
    const visible = ATTACK_VECTORS.filter(v => {
        if (filterSeverity !== 'all' && v.severity !== filterSeverity) return false;
        if (!needle) return true;
        return v.title.toLowerCase().includes(needle)
            || (v.cve && v.cve.toLowerCase().includes(needle))
            || v.target.toLowerCase().includes(needle);
    });

    const counts = { critical: 0, high: 0, medium: 0 };
    ATTACK_VECTORS.forEach(v => counts[v.severity]++);
    if (summary) {
        summary.innerHTML = `${ATTACK_VECTORS.length} vectors catalogued — ` +
            `<span class="sev-count critical">${counts.critical} critical</span>, ` +
            `<span class="sev-count high">${counts.high} high</span>, ` +
            `<span class="sev-count medium">${counts.medium} medium</span>` +
            (visible.length !== ATTACK_VECTORS.length ? ` · showing ${visible.length}` : '');
    }

    grid.innerHTML = visible.map(v => {
        const cveTag = v.cve
            ? `<span class="cve-tag">${escapeHtml(v.cve)}${v.disputed ? ' <em>(disputed)</em>' : ''}</span>`
            : `<span class="cve-tag cve-tag-none">No single CVE</span>`;
        const demoBody = v.demoList
            ? `<ul>${v.demoList.map(i => `<li>${escapeHtml(i)}</li>`).join('')}</ul>`
            : `<code>${escapeHtml(v.demoCode)}</code>`;
        const detailItems = v.details.map(d => `<li>${escapeHtml(d)}</li>`).join('');
        return `
            <div class="attack-card">
                <div class="attack-header">
                    <h3><i class="fas ${v.icon}"></i> ${escapeHtml(v.title)}</h3>
                    <span class="severity ${v.severity}">${v.severity}</span>
                    ${cveTag}
                </div>
                <p>${escapeHtml(v.summary)}</p>
                <p class="attack-target">${escapeHtml(v.target)}</p>
                <div class="attack-demo">
                    <h4>${escapeHtml(v.demoLabel)}</h4>
                    ${demoBody}
                    <button class="btn-attack" onclick="togglePoc('${v.id}')">Show proof-of-concept notes</button>
                    <div class="poc-panel" id="poc-${v.id}" hidden>
                        <ul>${detailItems}</ul>
                        <p class="poc-impact"><strong>Impact:</strong> ${escapeHtml(v.impact)}</p>
                    </div>
                </div>
            </div>`;
    }).join('');

    if (empty) empty.hidden = visible.length !== 0;
}

function togglePoc(id) {
    const panel = document.getElementById('poc-' + id);
    const btn = panel && panel.previousElementSibling;
    if (!panel) return;
    panel.hidden = !panel.hidden;
    if (btn && btn.classList.contains('btn-attack')) {
        btn.textContent = panel.hidden ? 'Show proof-of-concept notes' : 'Hide proof-of-concept notes';
    }
}

function initAttackVectorFilters() {
    const searchEl = document.getElementById('attack-search');
    const chips = document.querySelectorAll('#severity-filters .chip');
    let currentSeverity = 'all';

    const update = () => renderAttackVectors(searchEl ? searchEl.value : '', currentSeverity);

    if (searchEl) searchEl.addEventListener('input', update);
    chips.forEach(chip => {
        chip.addEventListener('click', () => {
            chips.forEach(c => c.classList.remove('active'));
            chip.classList.add('active');
            currentSeverity = chip.dataset.sev;
            update();
        });
    });

    renderAttackVectors();
}

// ===== Real cryptographic primitives (Web Crypto API) =====
// Every signing/verification tool below uses actual HMAC, not a simulation.

const HASH_BY_ALG = { HS256: 'SHA-256', HS384: 'SHA-384', HS512: 'SHA-512' };

const BUILTIN_SECRETS = [
    'secret', 'password', 'admin', '123456', 'jwt_secret', 'your-256-bit-secret',
    'your-secret-key', 'secretkey', 'key', 'mysecret', 'test', 'debug', 'dev',
    'production', 'changeme', 'letmein', 'qwerty', 'supersecret', 'supersecretkey',
    's3cr3t', 'jwtsecret', 'jwt-secret', 'shhhhh', 'p@ssw0rd', 'welcome', 'default',
    'demo', 'sample', '1234567890', 'abc123', 'topsecret', 'private',
    'encryption_key', 'hs256secret', 'symmetric-key', '0123456789abcdef',
    'my-secret', 'node_jwt_secret', 'express-secret'
];

function b64urlEncodeStr(str) {
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlToBytes(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    str += '='.repeat((4 - str.length % 4) % 4);
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

function bufToBase64Url(buf) {
    const bytes = new Uint8Array(buf);
    let binary = '';
    bytes.forEach(b => binary += String.fromCharCode(b));
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function atobUrl(str) {
    str += '='.repeat((4 - str.length % 4) % 4);
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    return atob(str);
}

async function hmacSign(hashName, secret, message) {
    const key = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(secret),
        { name: 'HMAC', hash: hashName }, false, ['sign']
    );
    return crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
}

function escapeHtml(str) {
    return String(str).replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
}

function toolResult(value, label, opts = {}) {
    const id = 'tool-out-' + Math.random().toString(36).slice(2, 9);
    const analyzeBtn = opts.analyze
        ? `<button class="btn-copy" onclick="sendToAnalyzer(document.getElementById('${id}').textContent)">Analyze</button>`
        : '';
    return `
        <div class="tool-result">
            <strong>${escapeHtml(label)}</strong>
            <code id="${id}" class="tool-code">${escapeHtml(value)}</code>
            <div class="tool-result-actions">
                <button class="btn-copy" onclick="copyToolResult('${id}')">Copy</button>
                ${analyzeBtn}
            </div>
        </div>`;
}

function toolMessage(msg, type = 'info') {
    return `<div class="tool-note tool-note-${type}">${escapeHtml(msg)}</div>`;
}

function copyToolResult(id) {
    const el = document.getElementById(id);
    if (!el) return;
    navigator.clipboard.writeText(el.textContent).then(() => {
        const btn = el.parentElement.querySelector('.btn-copy');
        if (btn) {
            const prev = btn.textContent;
            btn.textContent = 'Copied';
            setTimeout(() => { btn.textContent = prev; }, 1200);
        }
    }).catch(() => {});
}

function sendToAnalyzer(token) {
    document.getElementById('jwt-input').value = token;
    if (window.jwtApp) {
        window.jwtApp.switchTab('analyzer');
        window.jwtApp.analyzeJWT();
    }
}

function downloadText(filename, text) {
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
}

// ===== JWT Tools =====

async function encodeJWT() {
    const resultEl = document.getElementById('encoded-result');
    const payloadStr = document.getElementById('encode-payload').value;
    const secret = document.getElementById('encode-secret').value;
    const alg = document.getElementById('encode-alg').value;

    if (!payloadStr) {
        resultEl.innerHTML = toolMessage('Provide a JSON payload.', 'warn');
        return;
    }
    if (alg !== 'none' && !secret) {
        resultEl.innerHTML = toolMessage('Provide a secret, or choose alg "none".', 'warn');
        return;
    }

    try {
        const payload = JSON.parse(payloadStr);
        const header = { alg: alg === 'none' ? 'none' : alg, typ: 'JWT' };
        const encodedHeader = b64urlEncodeStr(JSON.stringify(header));
        const encodedPayload = b64urlEncodeStr(JSON.stringify(payload));
        const signingInput = `${encodedHeader}.${encodedPayload}`;

        let signature = '';
        if (alg !== 'none') {
            const sigBuf = await hmacSign(HASH_BY_ALG[alg], secret, signingInput);
            signature = bufToBase64Url(sigBuf);
        }

        const token = `${signingInput}.${signature}`;
        resultEl.innerHTML = toolResult(token, 'Generated JWT (real HMAC signature)', { analyze: true });
    } catch (error) {
        resultEl.innerHTML = toolMessage('Error encoding JWT: ' + error.message, 'error');
    }
}

async function verifyJWT() {
    const resultEl = document.getElementById('verify-result');
    const token = document.getElementById('verify-token').value.trim();
    const secret = document.getElementById('verify-secret').value;

    if (!token) {
        resultEl.innerHTML = toolMessage('Paste a token to verify.', 'warn');
        return;
    }

    try {
        const parts = token.split('.');
        if (parts.length !== 3) throw new Error('Invalid JWT format (expected 3 parts).');

        const header = JSON.parse(atobUrl(parts[0]));
        const signingInput = `${parts[0]}.${parts[1]}`;

        if (header.alg === 'none') {
            const unsigned = parts[2] === '';
            resultEl.innerHTML = toolMessage(
                unsigned
                    ? '"none" algorithm with an empty signature segment — if the server accepts this, authentication is fully bypassed.'
                    : '"none" algorithm with a non-empty signature segment — some parsers still accept this blindly.',
                'warn'
            );
            return;
        }

        const hashName = HASH_BY_ALG[header.alg];
        if (!hashName) {
            resultEl.innerHTML = toolMessage(
                `alg "${header.alg}" is not HMAC — this tool verifies HS256/384/512 locally. RS/ES/PS tokens need the public key, not a shared secret.`,
                'warn'
            );
            return;
        }
        if (!secret) {
            resultEl.innerHTML = toolMessage('Provide the candidate secret to check against.', 'warn');
            return;
        }

        const expectedSig = bufToBase64Url(await hmacSign(hashName, secret, signingInput));
        const valid = expectedSig === parts[2];
        resultEl.innerHTML = `<div class="tool-result"><strong>Result:</strong> <span class="${valid ? 'ok-text' : 'bad-text'}">${valid ? 'Signature valid — secret matches.' : 'Signature does not match this secret.'}</span></div>`;
    } catch (error) {
        resultEl.innerHTML = toolMessage('Error verifying JWT: ' + error.message, 'error');
    }
}

async function crackSecret() {
    const resultEl = document.getElementById('crack-result');
    const token = document.getElementById('crack-token').value.trim();
    const customList = document.getElementById('crack-wordlist').value;

    if (!token) {
        resultEl.innerHTML = toolMessage('Paste a token to attack.', 'warn');
        return;
    }

    const parts = token.split('.');
    if (parts.length !== 3) {
        resultEl.innerHTML = toolMessage('Invalid JWT format.', 'error');
        return;
    }

    let header;
    try {
        header = JSON.parse(atobUrl(parts[0]));
    } catch (error) {
        resultEl.innerHTML = toolMessage('Could not decode the header: ' + error.message, 'error');
        return;
    }

    const hashName = HASH_BY_ALG[header.alg];
    if (!hashName) {
        resultEl.innerHTML = toolMessage(`alg "${header.alg}" is not HMAC — a shared-secret brute force does not apply here.`, 'warn');
        return;
    }

    const signingInput = `${parts[0]}.${parts[1]}`;
    const wordlist = (customList.trim() ? customList.split('\n') : BUILTIN_SECRETS)
        .map(w => w.trim()).filter(Boolean);

    resultEl.innerHTML = toolMessage(`Trying ${wordlist.length} candidates against ${header.alg}…`, 'info');

    let found = null;
    for (let i = 0; i < wordlist.length; i++) {
        const candidate = wordlist[i];
        const sig = bufToBase64Url(await hmacSign(hashName, candidate, signingInput));
        if (sig === parts[2]) {
            found = candidate;
            break;
        }
        if (i % 25 === 0) {
            resultEl.innerHTML = toolMessage(`Trying ${wordlist.length} candidates against ${header.alg}… (${i + 1}/${wordlist.length})`, 'info');
            await new Promise(r => setTimeout(r, 0));
        }
    }

    if (found) {
        resultEl.innerHTML = toolResult(found, 'Secret cracked');
    } else {
        resultEl.innerHTML = toolMessage(
            `No match among ${wordlist.length} candidates. For a larger attack, export this token and try it offline with hashcat (-m 16500) or a bigger wordlist.`,
            'warn'
        );
    }
}

function loadForge() {
    const resultEl = document.getElementById('forge-result');
    const token = document.getElementById('forge-token').value.trim();
    const parts = token.split('.');

    if (parts.length !== 3) {
        resultEl.innerHTML = toolMessage('Invalid JWT format.', 'error');
        return;
    }

    try {
        const header = JSON.parse(atobUrl(parts[0]));
        const payload = JSON.parse(atobUrl(parts[1]));
        document.getElementById('forge-header').value = JSON.stringify(header, null, 2);
        document.getElementById('forge-payload').value = JSON.stringify(payload, null, 2);
        resultEl.innerHTML = toolMessage('Loaded. Edit the claims above, choose a signing mode, then forge.', 'info');
    } catch (error) {
        resultEl.innerHTML = toolMessage('Could not decode token: ' + error.message, 'error');
    }
}

async function forgeToken() {
    const resultEl = document.getElementById('forge-result');
    const mode = document.getElementById('forge-mode').value;
    const secret = document.getElementById('forge-secret').value;

    try {
        const header = JSON.parse(document.getElementById('forge-header').value || '{}');
        const payload = JSON.parse(document.getElementById('forge-payload').value || '{}');

        header.alg = mode === 'none' ? 'none' : 'HS256';
        const encodedHeader = b64urlEncodeStr(JSON.stringify(header));
        const encodedPayload = b64urlEncodeStr(JSON.stringify(payload));
        const signingInput = `${encodedHeader}.${encodedPayload}`;

        let signature = '';
        if (mode !== 'none') {
            if (!secret) throw new Error("Provide a secret (or the target's public key for the confusion mode).");
            signature = bufToBase64Url(await hmacSign('SHA-256', secret, signingInput));
        }

        const token = `${signingInput}.${signature}`;
        const note = mode === 'confusion'
            ? 'Forged with HS256, using the pasted text as the HMAC key. This only works if the server verifies with that exact public key treated as a raw secret (the CVE-2016-10555 class of bug).'
            : mode === 'none'
                ? 'Forged with alg: none. Only works if the server skips signature verification for this algorithm.'
                : 'Forged and resigned with the secret provided.';

        resultEl.innerHTML = toolResult(token, 'Forged JWT', { analyze: true }) + toolMessage(note, 'info');
    } catch (error) {
        resultEl.innerHTML = toolMessage('Error forging token: ' + error.message, 'error');
    }
}

async function inspectJWKS() {
    const resultEl = document.getElementById('jwks-result');
    const url = document.getElementById('jwks-url').value.trim();

    if (!url) {
        resultEl.innerHTML = toolMessage('Enter a JWKS URL.', 'warn');
        return;
    }

    resultEl.innerHTML = toolMessage('Fetching…', 'info');

    try {
        const res = await fetch(url, { mode: 'cors' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const keys = data.keys || [];

        if (!keys.length) {
            resultEl.innerHTML = toolMessage('No "keys" array found in the response.', 'warn');
            return;
        }

        const kidCounts = {};
        keys.forEach(k => { kidCounts[k.kid] = (kidCounts[k.kid] || 0) + 1; });

        const rows = keys.map(k => {
            const flags = [];
            if (k.kid && kidCounts[k.kid] > 1) flags.push('duplicate kid');
            if (k.kty === 'oct') flags.push('symmetric key exposed');
            return `<tr>
                <td>${escapeHtml(k.kid ?? '—')}</td>
                <td>${escapeHtml(k.kty ?? '—')}</td>
                <td>${escapeHtml(k.alg ?? '—')}</td>
                <td>${escapeHtml(k.use ?? '—')}</td>
                <td>${flags.length ? escapeHtml(flags.join(', ')) : '—'}</td>
            </tr>`;
        }).join('');

        resultEl.innerHTML = `
            <div class="tool-result">
                <strong>${keys.length} key(s) found</strong>
                <table class="jwks-table">
                    <thead><tr><th>kid</th><th>kty</th><th>alg</th><th>use</th><th>flags</th></tr></thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>
            ${toolMessage('A duplicate kid shared between an RSA and an "oct" (symmetric) key is the classic setup for JWKS/algorithm confusion. A kty:"oct" entry means a symmetric secret is exposed at a public endpoint.', 'info')}
        `;
    } catch (error) {
        resultEl.innerHTML = toolMessage('Fetch failed: ' + error.message + ' (often CORS — try testing from the target\'s own origin, or via Burp).', 'error');
    }
}

function convertTimestamp() {
    const resultEl = document.getElementById('timestamp-result');
    const timestamp = document.getElementById('timestamp-input').value;

    if (!timestamp) {
        resultEl.innerHTML = toolMessage('Provide a Unix timestamp.', 'warn');
        return;
    }

    try {
        const date = new Date(parseInt(timestamp, 10) * 1000);
        if (isNaN(date.getTime())) throw new Error('Not a valid timestamp.');
        resultEl.innerHTML = `
            <div class="tool-result">
                <strong>Converted time</strong>
                <code class="tool-code">${escapeHtml(date.toLocaleString())}</code>
                <code class="tool-code">UTC: ${escapeHtml(date.toUTCString())}</code>
            </div>
        `;
    } catch (error) {
        resultEl.innerHTML = toolMessage('Error converting timestamp: ' + error.message, 'error');
    }
}

function generateWordlist() {
    const type = document.getElementById('wordlist-type').value;
    let wordlist = [];

    switch (type) {
        case 'common':
            wordlist = BUILTIN_SECRETS;
            break;
        case 'numeric':
            wordlist = ['123456', '000000', '111111', '123123', '654321', '999999', '121212', '112233'];
            break;
        case 'alphanumeric':
            wordlist = ['abc123', 'test123', 'admin123', 'pass123', 'user123', 'secret1', 'jwt12345'];
            break;
    }

    document.getElementById('wordlist-result').innerHTML = `
        <div class="tool-result">
            <strong>Generated wordlist (${wordlist.length} entries)</strong>
            <div class="wordlist-box">
                ${wordlist.map(word => `<div class="wordlist-entry">${escapeHtml(word)}</div>`).join('')}
            </div>
            <div class="tool-result-actions">
                <button class="btn-copy" id="wordlist-download">Download .txt</button>
            </div>
        </div>
    `;
    document.getElementById('wordlist-download').addEventListener('click', () => {
        downloadText('jwt-wordlist.txt', wordlist.join('\n'));
    });
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    window.jwtApp = new JWTSecurityAssessment();
    initAttackVectorFilters();
});
