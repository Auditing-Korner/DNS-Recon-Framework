"""
Constants for DNS tools
"""

# Common SMTP security issues
SMTP_SECURITY_CHECKS = {
    "open_relay": {
        "ports": [25, 587, 465],
        "test_commands": [
            "HELO test.com",
            "MAIL FROM: test@test.com",
            "RCPT TO: test@test.com",
            "DATA",
            "Subject: Test",
            ".",
            "QUIT"
        ]
    },
    "starttls_required": {
        "ports": [25, 587]
    },
    "banner_check": {
        "dangerous_strings": [
            "postfix",
            "exim",
            "sendmail",
            "microsoft smtp server"
        ]
    }
}

# Common subdomain takeover signatures
TAKEOVER_SIGNATURES = {
    "AWS/S3": {
        "signatures": [
            "NoSuchBucket",
            "The specified bucket does not exist",
            "S3 Bucket not found"
        ],
        "cname_patterns": [
            r"\.s3\.amazonaws\.com$",
            r"\.s3-[a-z0-9-]+\.amazonaws\.com$"
        ]
    },
    "GitHub Pages": {
        "signatures": [
            "There isn't a GitHub Pages site here",
            "404: Not Found",
            "No such app"
        ],
        "cname_patterns": [
            r"\.github\.io$",
            r"\.githubusercontent\.com$"
        ]
    },
    "Heroku": {
        "signatures": [
            "No such app",
            "herokucdn.com/error-pages/no-such-app.html",
            "Nothing to see here",
            "Building a brand new app"
        ],
        "cname_patterns": [
            r"\.herokuapp\.com$",
            r"\.herokudns\.com$"
        ]
    },
    "Fastly": {
        "signatures": [
            "Fastly error: unknown domain",
            "Unknown domain",
            "Fatal Error"
        ],
        "cname_patterns": [
            r"\.fastly\.net$"
        ]
    }
}

# Security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "HSTS enforces secure (HTTPS) connections to the server",
        "recommended": "max-age=31536000; includeSubDomains; preload"
    },
    "X-Frame-Options": {
        "description": "Protects against clickjacking attacks",
        "recommended": ["DENY", "SAMEORIGIN"]
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing",
        "recommended": "nosniff"
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS and other injection attacks",
        "recommended": "default-src 'self'"
    },
    "X-XSS-Protection": {
        "description": "Enables browser XSS filtering",
        "recommended": "1; mode=block"
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information should be included",
        "recommended": ["strict-origin", "strict-origin-when-cross-origin", "no-referrer"]
    },
    "Permissions-Policy": {
        "description": "Controls which features and APIs can be used",
        "recommended": "geolocation=(), microphone=()"
    }
}

# DNS record types to check
RECORD_TYPES = [
    'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'PTR', 'SRV', 'CAA', 
    'DNSKEY', 'DS', 'NSEC', 'NSEC3', 'HTTPS', 'SVCB', 'DNAME'
]

# DNSSEC record types to check
DNSSEC_RECORD_TYPES = ['DNSKEY', 'DS', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'RRSIG']

# DNSSEC algorithm numbers and their meanings
DNSSEC_ALGORITHMS = {
    0: "Delete DS",
    1: "RSA/MD5 (deprecated)",
    2: "Diffie-Hellman",
    3: "DSA/SHA1",
    5: "RSA/SHA-1",
    6: "DSA-NSEC3-SHA1",
    7: "RSASHA1-NSEC3-SHA1",
    8: "RSA/SHA-256",
    10: "RSA/SHA-512",
    12: "GOST R 34.10-2001",
    13: "ECDSA Curve P-256 with SHA-256",
    14: "ECDSA Curve P-384 with SHA-384",
    15: "Ed25519",
    16: "Ed448"
}

# DNSSEC digest types
DNSSEC_DIGEST_TYPES = {
    1: "SHA-1",
    2: "SHA-256",
    3: "GOST R 34.11-94",
    4: "SHA-384"
} 