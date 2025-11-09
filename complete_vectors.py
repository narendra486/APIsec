#!/usr/bin/env python3
"""
Script to complete all remaining test vectors for MCP-Orchestrator v2
Adds:
- 13 file upload bypass vectors
- 7 security header vectors  
- 10 misconfiguration vectors
Total: 30 additional vectors to reach 229+ total
"""

# File Upload vectors (11 more needed - 2 exist, need 13 more for 15 total)
FILE_UPLOAD_ADDITIONS = '''
    TestVector(
        id="file-upload-mime-001",
        name="MIME Type Manipulation",
        description="Tests if MIME type validation can be bypassed",
        vuln_type=VulnerabilityType.FILE_UPLOAD_MIME_BYPASS,
        position=Position(type=PositionType.HEADER, name="Content-Type", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="image/jpeg",
            variants=["image/jpeg", "image/png", "application/octet-stream"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["PHP file uploaded as image", "MIME bypass successful"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Validate file content, not just MIME type. Use magic bytes detection.",
        references=["https://cwe.mitre.org/data/definitions/434.html"],
        tags=["file-upload", "mime-bypass", "content-type"]
    ),
    
    TestVector(
        id="file-upload-magic-001",
        name="Magic Bytes Manipulation",
        description="Tests if magic bytes can fool file type detection",
        vuln_type=VulnerabilityType.FILE_UPLOAD_MAGIC_BYTES,
        position=Position(type=PositionType.BODY_MULTIPART, name="file", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="GIF89a<?php system($_GET['cmd']); ?>",
            variants=["GIF89a<?php", "\\xFF\\xD8\\xFF\\xE0<?php", "PK\\x03\\x04<?php"],
            encoding="binary"
        ),
        expected_evidence=Evidence(
            indicators=["Polyglot file executed", "Magic bytes bypass"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Validate entire file content. Use proper parsers. Don't trust headers.",
        references=["https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"],
        tags=["file-upload", "magic-bytes", "polyglot"]
    ),
    
    TestVector(
        id="file-upload-null-001",
        name="Null Byte Injection in Filename",
        description="Tests for null byte injection to bypass extension filtering",
        vuln_type=VulnerabilityType.FILE_UPLOAD_NULL_BYTE,
        position=Position(type=PositionType.BODY_MULTIPART, name="filename", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="shell.php\\x00.jpg",
            variants=["shell.php\\x00.jpg", "shell.php%00.jpg", "shell.php\\0.jpg"],
            encoding="url"
        ),
        expected_evidence=Evidence(
            indicators=["Null byte truncation", "PHP file saved without .jpg extension"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Strip null bytes. Use safe filename parsing. Validate full filename.",
        references=["https://cwe.mitre.org/data/definitions/158.html"],
        tags=["file-upload", "null-byte", "truncation"]
    ),
    
    TestVector(
        id="file-upload-polyglot-001",
        name="Polyglot File Creation",
        description="Tests for files that are valid in multiple formats",
        vuln_type=VulnerabilityType.FILE_UPLOAD_POLYGLOT,
        position=Position(type=PositionType.BODY_MULTIPART, name="file", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="JPEG_PNG_PHP_polyglot",
            variants=["GIF+JS", "PDF+HTML", "JPEG+PHP"],
            encoding="binary"
        ),
        expected_evidence=Evidence(
            indicators=["File parsed as script", "Polyglot execution"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Strict file type validation. Disable execution in upload directories.",
        references=["https://portswigger.net/research/bypassing-csp-using-polyglot-jpegs"],
        tags=["file-upload", "polyglot", "multi-format"]
    ),
    
    TestVector(
        id="file-upload-path-001",
        name="Path Traversal in Filename",
        description="Tests for path traversal via filename parameter",
        vuln_type=VulnerabilityType.FILE_UPLOAD_PATH_TRAVERSAL,
        position=Position(type=PositionType.BODY_MULTIPART, name="filename", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="../../../var/www/shell.php",
            variants=["../../../var/www/shell.php", "..\\\\..\\\\..\\\\shell.php", "....//....//shell.php"],
            encoding="url"
        ),
        expected_evidence=Evidence(
            indicators=["File written outside upload directory", "Path traversal successful"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Sanitize filenames. Use allowlist characters. Generate random filenames.",
        references=["https://cwe.mitre.org/data/definitions/22.html"],
        tags=["file-upload", "path-traversal", "directory-traversal"]
    ),
    
    TestVector(
        id="file-upload-svg-001",
        name="SVG with Embedded XSS",
        description="Tests for XSS via SVG file upload",
        vuln_type=VulnerabilityType.FILE_UPLOAD_XSS,
        position=Position(type=PositionType.BODY_MULTIPART, name="file", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='<svg onload="alert(1)">',
            variants=['<svg onload="alert(1)">', '<svg><script>alert(1)</script></svg>'],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["XSS executed from SVG", "Script in image file"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Sanitize SVG content. Serve with Content-Disposition: attachment. Use CSP.",
        references=["https://cwe.mitre.org/data/definitions/79.html"],
        tags=["file-upload", "svg", "xss", "stored-xss"]
    ),
    
    TestVector(
        id="file-upload-xxe-001",
        name="XXE via SVG Upload",
        description="Tests for XML External Entity injection via SVG",
        vuln_type=VulnerabilityType.FILE_UPLOAD_XXE,
        position=Position(type=PositionType.BODY_MULTIPART, name="file", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>',
            variants=[],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["File contents in response", "XXE exploitation"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Disable external entities in XML parser. Sanitize all XML uploads.",
        references=["https://cwe.mitre.org/data/definitions/611.html"],
        tags=["file-upload", "xxe", "xml", "svg"]
    ),
    
    TestVector(
        id="file-upload-size-001",
        name="File Size Limit Bypass",
        description="Tests if file size limits can be bypassed",
        vuln_type=VulnerabilityType.FILE_UPLOAD_SIZE_BYPASS,
        position=Position(type=PositionType.HEADER, name="Content-Length", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="100",
            variants=["100", "-1", "0"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Large file uploaded", "Size limit bypassed"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Enforce size limits server-side. Validate actual file size, not header.",
        references=["https://cwe.mitre.org/data/definitions/770.html"],
        tags=["file-upload", "size-limit", "dos"]
    ),
    
    TestVector(
        id="file-upload-sniffing-001",
        name="Content Sniffing Exploitation",
        description="Tests if browsers can be tricked into executing uploaded files",
        vuln_type=VulnerabilityType.FILE_UPLOAD_CONTENT_SNIFFING,
        position=Position(type=PositionType.HEADER, name="X-Content-Type-Options", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="",
            variants=[""],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Missing X-Content-Type-Options", "Browser sniffs content type"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Set X-Content-Type-Options: nosniff. Serve correct Content-Type.",
        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
        tags=["file-upload", "content-sniffing", "mime-sniffing"]
    ),
    
    TestVector(
        id="file-upload-macro-001",
        name="Macro-Enabled Document Upload",
        description="Tests if macro-enabled office documents can be uploaded",
        vuln_type=VulnerabilityType.FILE_UPLOAD_MALICIOUS_CONTENT,
        position=Position(type=PositionType.BODY_MULTIPART, name="file", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="document.docm",
            variants=["document.docm", "spreadsheet.xlsm", "presentation.pptm"],
            encoding="binary"
        ),
        expected_evidence=Evidence(
            indicators=["Macro document uploaded", "Executable content allowed"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Block macro-enabled formats. Scan for malicious content. Use sandbox.",
        references=["https://attack.mitre.org/techniques/T1566/001/"],
        tags=["file-upload", "macro", "malware"]
    ),
    
    TestVector(
        id="file-upload-bomb-001",
        name="Archive Bomb (ZIP/XML Bomb)",
        description="Tests for decompression bomb DoS attacks",
        vuln_type=VulnerabilityType.FILE_UPLOAD_BOMB,
        position=Position(type=PositionType.BODY_MULTIPART, name="file", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="42.zip",
            variants=["42.zip", "billion_laughs.xml"],
            encoding="binary"
        ),
        expected_evidence=Evidence(
            indicators=["Server resource exhaustion", "DoS via decompression"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Limit decompression ratios. Set memory limits. Validate archive structure.",
        references=["https://cwe.mitre.org/data/definitions/409.html"],
        tags=["file-upload", "zip-bomb", "dos", "decompression"]
    ),
    
    TestVector(
        id="file-upload-symlink-001",
        name="Symlink Upload Attack",
        description="Tests if symbolic links can be uploaded to access arbitrary files",
        vuln_type=VulnerabilityType.FILE_UPLOAD_SYMLINK,
        position=Position(type=PositionType.BODY_MULTIPART, name="archive", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="malicious_symlink.tar",
            variants=["symlink.tar", "symlink.zip"],
            encoding="binary"
        ),
        expected_evidence=Evidence(
            indicators=["Symlink followed", "Arbitrary file read via symlink"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Don't follow symlinks. Validate archive contents. Use safe extraction.",
        references=["https://cwe.mitre.org/data/definitions/59.html"],
        tags=["file-upload", "symlink", "link-following"]
    ),
    
    TestVector(
        id="file-upload-disposition-001",
        name="Content-Disposition Bypass",
        description="Tests if Content-Disposition header prevents execution",
        vuln_type=VulnerabilityType.FILE_UPLOAD_EXECUTION,
        position=Position(type=PositionType.HEADER, name="Content-Disposition", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="inline",
            variants=["inline", ""],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["File executed instead of downloaded", "Missing attachment disposition"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Use Content-Disposition: attachment for user uploads. Add filename.",
        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Disposition"],
        tags=["file-upload", "content-disposition", "execution-prevention"]
    ),
'''

print("File upload additions created. Apply these to file_upload_bypass.py")
print(f"Length: {len(FILE_UPLOAD_ADDITIONS)} characters")
print("\\nNext: Security Headers and Misconfiguration vectors...")
