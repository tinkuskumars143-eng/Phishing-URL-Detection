

/* =========================================
   PhishGuard - Phishing URL Detector
   URL Analysis and Result Display
========================================= */

document.addEventListener("DOMContentLoaded", () => {
    const scanForm = document.getElementById("scanForm");
    const urlInput = document.getElementById("urlInput");
    const scanButton = document.getElementById("scanButton");
    const resultBox = document.getElementById("result");

    // Check whether the required HTML elements exist
    if (!scanForm || !urlInput || !scanButton || !resultBox) {
        console.error(
            "PhishGuard Error: Required HTML elements not found."
        );
        return;
    }

    // Common URL shortener domains
    const shortenerDomains = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly",
        "rb.gy",
        "shorturl.at"
    ];

    // Words commonly found in suspicious URLs
    const suspiciousWords = [
        "login",
        "verify",
        "verification",
        "password",
        "account",
        "update",
        "secure",
        "banking",
        "wallet",
        "confirm",
        "signin",
        "credential"
    ];

    // Display a message safely
    function showMessage(title, message, type = "error") {
        resultBox.hidden = false;

        const colors = {
            error: "#ef4444",
            warning: "#f59e0b",
            safe: "#22c55e"
        };

        resultBox.replaceChildren();

        const heading = document.createElement("h3");
        heading.textContent = title;
        heading.style.color = colors[type] || colors.error;

        const paragraph = document.createElement("p");
        paragraph.textContent = message;

        resultBox.append(heading, paragraph);
        resultBox.scrollIntoView({
            behavior: "smooth",
            block: "nearest"
        });
    }

    // Check whether hostname is an IPv4 address
    function isIPAddress(hostname) {
        const parts = hostname.split(".");

        return (
            parts.length === 4 &&
            parts.every(part =>
                /^\d{1,3}$/.test(part) &&
                Number(part) >= 0 &&
                Number(part) <= 255
            )
        );
    }

    // Check whether a hostname is a known URL shortener
    function isShortener(hostname) {
        return shortenerDomains.some(domain =>
            hostname === domain ||
            hostname.endsWith("." + domain)
        );
    }

    // Analyze URL patterns
    function analyzeURL(url) {
        const warnings = [];
        let score = 0;

        const hostname = url.hostname.toLowerCase();
        const fullURL = url.href.toLowerCase();

        // 1. Check HTTP instead of HTTPS
        if (url.protocol === "http:") {
            warnings.push(
                "The URL uses HTTP instead of HTTPS."
            );
            score += 1;
        }

        // 2. Check IP address as hostname
        if (isIPAddress(hostname)) {
            warnings.push(
                "The website uses an IP address instead of a domain name."
            );
            score += 2;
        }

        // 3. Check the @ symbol in the URL
        if (url.username || url.password || url.href.includes("@")) {
            warnings.push(
                "The URL contains an @ symbol or embedded login information."
            );
            score += 2;
        }

        // 4. Check unusually long URLs
        if (url.href.length > 100) {
            warnings.push(
                "The URL is unusually long."
            );
            score += 1;
        }

        // 5. Check excessive subdomains
        const domainParts = hostname.split(".");

        if (domainParts.length >= 5) {
            warnings.push(
                "The domain contains many subdomain levels."
            );
            score += 2;
        }

        // 6. Check suspicious keywords
        const foundWords = suspiciousWords.filter(word =>
            fullURL.includes(word)
        );

        if (foundWords.length > 0) {
            warnings.push(
                "Potentially sensitive keywords found: " +
                foundWords.join(", ") + "."
            );
            score += 1;
        }

        // 7. Check URL shorteners
        if (isShortener(hostname)) {
            warnings.push(
                "This is a URL-shortening service. The final destination is not visible here."
            );
            score += 2;
        }

        // 8. Check hyphens in hostname
        if (hostname.split(".")[0].includes("-")) {
            warnings.push(
                "The hostname contains hyphens. Verify the domain carefully."
            );
            score += 1;
        }

        // 9. Check punycode domains
        if (hostname.includes("xn--")) {
            warnings.push(
                "The domain contains punycode, which can be used in lookalike domains."
            );
            score += 2;
        }

        // 10. Check unusual URL characters
        if (/%[0-9a-f]{2}/i.test(url.pathname + url.search)) {
            warnings.push(
                "The URL contains encoded characters. Inspect the destination carefully."
            );
            score += 1;
        }

        // 11. Check suspicious file extensions
        if (/\.(exe|scr|bat|cmd|msi|apk)(\/|$)/i.test(url.pathname)) {
            warnings.push(
                "The URL path points to a potentially risky executable or application file."
            );
            score += 2;
        }

        return { warnings, score };
    }

    // Handle the Scan URL form
    scanForm.addEventListener("submit", function (event) {
        event.preventDefault();

        const input = urlInput.value.trim();

        // Validate empty input
        if (!input) {
            showMessage(
                "URL Required",
                "Please enter a website URL before scanning.",
                "error"
            );
            urlInput.focus();
            return;
        }

        // Reject spaces and control characters
        if (/\s/.test(input)) {
            showMessage(
                "Invalid URL",
                "The URL must not contain spaces. Please check your input.",
                "error"
            );
            return;
        }

        // Accept URLs without an explicitly written protocol
        let normalizedURL = input;

        if (!/^[a-z][a-z0-9+.-]*:/i.test(normalizedURL)) {
            normalizedURL = "https://" + normalizedURL;
        }

        let parsedURL;

        try {
            parsedURL = new URL(normalizedURL);
        } catch {
            showMessage(
                "Invalid URL",
                "Please enter a valid URL, such as https://example.com.",
                "error"
            );
            return;
        }

        // Only allow web URLs
        if (
            !["http:", "https:"].includes(parsedURL.protocol) ||
            !parsedURL.hostname ||
            !parsedURL.hostname.includes(".") ||
            parsedURL.hostname.startsWith(".") ||
            parsedURL.hostname.endsWith(".")
        ) {
            showMessage(
                "Invalid Website URL",
                "Please enter a valid HTTP or HTTPS website address.",
                "error"
            );
            return;
        }

        // Show scanning status
        scanButton.disabled = true;
        scanButton.textContent = "Scanning...";
        resultBox.hidden = true;

        try {
            const { warnings, score } = analyzeURL(parsedURL);

            resultBox.replaceChildren();
            resultBox.hidden = false;

            const heading = document.createElement("h3");
            const description = document.createElement("p");
            const scannedURL = document.createElement("p");
            const detailsHeading = document.createElement("h4");
            const warningList = document.createElement("ul");
            const note = document.createElement("p");

            scannedURL.textContent =
                "Scanned URL: " + parsedURL.href;

            detailsHeading.textContent = "Detection Details";

            note.textContent =
                "Note: This is a basic URL pattern check, not a live threat intelligence scan. A website may still be malicious even if no warning signs are detected.";

            note.style.borderTop = "1px solid rgba(255,255,255,0.15)";
            note.style.paddingTop = "12px";

            if (score >= 4) {
                heading.textContent =
                    "⚠️ Potentially Suspicious URL";

                heading.style.color = "#ef4444";

                description.textContent =
                    "Several warning indicators were detected. Verify the website independently before interacting with it.";

                resultBox.style.borderLeft =
                    "4px solid #ef4444";

            } else if (score >= 2) {
                heading.textContent =
                    "⚠️ Caution: Review This URL";

                heading.style.color = "#f59e0b";

                description.textContent =
                    "Some warning indicators were detected. Check the domain and destination carefully.";

                resultBox.style.borderLeft =
                    "4px solid #f59e0b";

            } else {
                heading.textContent =
                    "✓ No Obvious Warning Signs";

                heading.style.color = "#22c55e";

                description.textContent =
                    "Basic checks did not identify many warning signs. This does NOT guarantee that the website is safe.";

                resultBox.style.borderLeft =
                    "4px solid #22c55e";
            }

            if (warnings.length > 0) {
                warnings.forEach(warning => {
                    const item = document.createElement("li");
                    item.textContent = warning;
                    warningList.appendChild(item);
                });
            } else {
                const item = document.createElement("li");
                item.textContent =
                    "No warning patterns were detected by these basic checks.";
                warningList.appendChild(item);
            }

            resultBox.append(
                heading,
                description,
                scannedURL,
                detailsHeading,
                warningList,
                note
            );

            resultBox.scrollIntoView({
                behavior: "smooth",
                block: "nearest"
            });

        } catch (error) {
            console.error("PhishGuard scan error:", error);

            showMessage(
                "Scan Error",
                "Something went wrong. Please check the URL and try again.",
                "error"
            );

        } finally {
            scanButton.disabled = false;
            scanButton.textContent = "Scan URL →";
        }
    });

    // Hide old results when the user edits the URL
    urlInput.addEventListener("input", () => {
        resultBox.hidden = true;
    });

    console.log("PhishGuard JavaScript loaded successfully.");
});


/* ==========================================
   PhishGuard - Improved URL Risk Analyzer
   Client-side heuristic detection
========================================== */

"use strict";

const scanForm = document.getElementById("scanForm");
const urlInput = document.getElementById("urlInput");
const scanButton = document.getElementById("scanButton");
const resultBox = document.getElementById("result");

const SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "rebrand.ly",
    "ow.ly"
];

const SUSPICIOUS_WORDS = [
    "login",
    "log-in",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "password",
    "credential",
    "account",
    "wallet",
    "banking",
    "payment",
    "confirm",
    "recover",
    "suspended",
    "secure",
    "update",
    "webscr",
    "authenticate"
];

// Common brands used for basic impersonation checks.
// This list is not exhaustive.
const BRANDS = [
    { name: "google", domain: "google.com" },
    { name: "microsoft", domain: "microsoft.com" },
    { name: "apple", domain: "apple.com" },
    { name: "paypal", domain: "paypal.com" },
    { name: "amazon", domain: "amazon.com" },
    { name: "facebook", domain: "facebook.com" },
    { name: "instagram", domain: "instagram.com" },
    { name: "netflix", domain: "netflix.com" }
];

const SUSPICIOUS_TLDS = [
    "click",
    "top",
    "work",
    "country",
    "gq",
    "tk"
];

function addFinding(findings, points, message) {
    findings.push({ points, message });
}

function isIpAddress(hostname) {
    // IPv4 check
    const ipv4 =
        /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);

    if (ipv4) {
        const parts = hostname.split(".").map(Number);
        return parts.every(part => part >= 0 && part <= 255);
    }

    // IPv6 addresses are returned with brackets by URL.hostname
    return hostname.startsWith("[") &&
        hostname.endsWith("]");
}

function isOfficialDomain(hostname, domain) {
    return hostname === domain ||
        hostname.endsWith("." + domain);
}

function hasBrandImpersonation(hostname) {
    return BRANDS.find(brand => {
        const brandPattern = new RegExp(
            "(^|[.-])" + brand.name + "([.-]|$)",
            "i"
        );

        return brandPattern.test(hostname) &&
            !isOfficialDomain(hostname, brand.domain);
    });
}

function analyzeUrl(input) {
    const findings = [];
    let parsedUrl;

    const trimmed = input.trim();

    if (!trimmed) {
        return {
            error: "Please enter a website URL."
        };
    }

    if (/\s/.test(trimmed)) {
        return {
            error: "The URL contains spaces. Please check it."
        };
    }

    // Add a scheme when the user enters google.com
    const candidate = /^[a-zA-Z][a-zA-Z\d+.-]*:/.test(trimmed)
        ? trimmed
        : "https://" + trimmed;

    try {
        parsedUrl = new URL(candidate);
    } catch {
        return {
            error: "Invalid URL. Please enter a valid domain or URL."
        };
    }

    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
        return {
            error: "Only HTTP and HTTPS website URLs are supported."
        };
    }

    if (!parsedUrl.hostname || !parsedUrl.hostname.includes(".")) {
        return {
            error: "Please enter a valid website hostname, such as example.com."
        };
    }

    const hostname = parsedUrl.hostname
        .toLowerCase()
        .replace(/\.$/, "");

    const fullUrl = parsedUrl.href;
    const lowerUrl = fullUrl.toLowerCase();
    const pathname = parsedUrl.pathname.toLowerCase();
    const isIp = isIpAddress(hostname);

    // 1. Connection protocol
    if (parsedUrl.protocol === "http:") {
        addFinding(
            findings,
            1,
            "The URL uses HTTP instead of HTTPS. The connection is not encrypted by HTTPS."
        );
    }

    // 2. IP address instead of a domain
    if (isIp) {
        addFinding(
            findings,
            3,
            "The website uses an IP address instead of a regular domain name."
        );
    }

    // 3. Credentials embedded in the URL
    if (parsedUrl.username || parsedUrl.password) {
        addFinding(
            findings,
            4,
            "The URL contains username or password information before the hostname."
        );
    }

    // 4. Punycode / internationalized hostname
    if (hostname.includes("xn--")) {
        addFinding(
            findings,
            2,
            "The hostname contains punycode. Check carefully for look-alike characters."
        );
    }

    // 5. Unusually long URL
    if (fullUrl.length > 150) {
        addFinding(
            findings,
            2,
            "The URL is unusually long, which can make its real destination harder to inspect."
        );
    }

    // 6. Too many subdomains
    const labels = hostname.split(".");
    if (labels.length >= 5) {
        addFinding(
            findings,
            2,
            "The hostname contains many domain sections or subdomains."
        );
    }

    // 7. Brand impersonation in the hostname
    const impersonatedBrand = hasBrandImpersonation(hostname);

    if (impersonatedBrand) {
        addFinding(
            findings,
            4,
            "The hostname mentions " + impersonatedBrand.name +
            " but is not on its official domain."
        );
    }

    // 8. URL shortener
    if (SHORTENERS.includes(hostname)) {
        addFinding(
            findings,
            2,
            "This is a URL-shortening service. The final destination is hidden."
        );
    }

    // 9. Suspicious words in URL
    const matchedWords = SUSPICIOUS_WORDS.filter(word =>
        lowerUrl.includes(word)
    );

    if (matchedWords.length > 0) {
        addFinding(
            findings,
            1,
            "The URL contains potentially sensitive keywords: " +
            matchedWords.slice(0, 5).join(", ") + "."
        );
    }

    // 10. Hyphenated hostname
    if (hostname.split(".")[0].includes("-")) {
        addFinding(
            findings,
            1,
            "The main hostname contains a hyphen. Verify the domain carefully."
        );
    }

    // 11. Selected uncommon TLDs
    const tld = hostname.split(".").pop();

    if (SUSPICIOUS_TLDS.includes(tld)) {
        addFinding(
            findings,
            1,
            "The domain uses a TLD that deserves additional scrutiny. A TLD alone does not prove a site is malicious."
        );
    }

    // 12. Encoded characters
    if (/%[0-9a-f]{2}/i.test(fullUrl)) {
        addFinding(
            findings,
            1,
            "The URL contains percent-encoded characters. Inspect the destination carefully."
        );
    }

    // 13. Executable or script-like file paths
    if (/\.(exe|msi|scr|bat|cmd|ps1|apk|jar)(?:$|[?#])/i.test(fullUrl)) {
        addFinding(
            findings,
            3,
            "The URL appears to point to a potentially risky downloadable file."
        );
    }

    // 14. Unusual port
    if (parsedUrl.port &&
        !["80", "443"].includes(parsedUrl.port)) {
        addFinding(
            findings,
            1,
            "The URL uses a non-standard web port."
        );
    }

    const score = findings.reduce(
        (total, finding) => total + finding.points,
        0
    );

    let level;
    let title;
    let className;

    if (score >= 6) {
        level = "high";
        title = "High Risk Indicators";
        className = "result-danger";
    } else if (score >= 3) {
        level = "caution";
        title = "Suspicious URL - Use Caution";
        className = "result-warning";
    } else {
        level = "low";
        title = "No Obvious Warning Signs";
        className = "result-safe";
    }

    return {
        level,
        title,
        className,
        score,
        findings,
        hostname,
        normalizedUrl: fullUrl
    };
}

function addTextElement(parent, tag, text, className = "") {
    const element = document.createElement(tag);
    element.textContent = text;

    if (className) {
        element.className = className;
    }

    parent.appendChild(element);
    return element;
}

function showResult(data) {
    resultBox.replaceChildren();
    resultBox.hidden = false;
    resultBox.className = "result-box";

    if (data.error) {
        resultBox.classList.add("result-error");
        addTextElement(resultBox, "h3", "Unable to Analyze URL");
        addTextElement(resultBox, "p", data.error);
        return;
    }

    resultBox.classList.add(data.className);

    const heading = document.createElement("h3");
    heading.textContent =
        (data.level === "low" ? "✓ " :
            data.level === "caution" ? "⚠ " : "✕ ") +
        data.title;

    resultBox.appendChild(heading);

    addTextElement(
        resultBox,
        "p",
        "Analyzed hostname: " + data.hostname
    );

    addTextElement(
        resultBox,
        "p",
        "Heuristic risk score: " + data.score +
        " points (not a probability of being malicious)."
    );

    const details = document.createElement("details");
    details.open = true;

    addTextElement(details, "summary", "Detection Details");

    const list = document.createElement("ul");

    if (data.findings.length === 0) {
        addTextElement(
            list,
            "li",
            "No warning patterns were detected by these basic checks."
        );
    } else {
        data.findings.forEach(finding => {
            addTextElement(list, "li", finding.message);
        });
    }

    details.appendChild(list);
    resultBox.appendChild(details);

    addTextElement(
        resultBox,
        "p",
        "Important: This is a basic URL pattern check, not a live threat-intelligence scan. A low score does not guarantee that a website is safe."
    );
}

scanForm.addEventListener("submit", function (event) {
    event.preventDefault();

    const originalButtonText = scanButton.textContent;

    scanButton.disabled = true;
    scanButton.textContent = "Analyzing...";

    try {
        const result = analyzeUrl(urlInput.value);
        showResult(result);
    } catch (error) {
        console.error("PhishGuard scanner error:", error);

        showResult({
            error: "Something went wrong while analyzing the URL. Please try again."
        });
    } finally {
        scanButton.disabled = false;
        scanButton.textContent = originalButtonText;
    }
});