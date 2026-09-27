from urllib.parse import urlparse

def check_url(url):
    suspicious_words = [
        "login", "verify", "update",
        "free", "secure", "banking"
    ]

    parsed = urlparse(url if "://" in url else "https://" + url)
    domain = parsed.netloc.lower()

    score = 0
    reasons = []

    if parsed.scheme != "https":
        score += 1
        reasons.append("HTTPS is not used")

    if "@" in url:
        score += 2
        reasons.append("@ symbol found in URL")

    if len(url) > 75:
        score += 1
        reasons.append("URL is unusually long")

    if domain.count(".") >= 3:
        score += 1
        reasons.append("Too many subdomains")

    if any(word in url.lower() for word in suspicious_words):
        score += 1
        reasons.append("Suspicious keyword found")

    print("\nURL:", url)

    if score >= 2:
        print("Result: Potentially Suspicious URL")
    else:
        print("Result: No obvious warning detected")

    if reasons:
        print("Warnings:")
        for reason in reasons:
            print("-", reason)



import streamlit as st
from urllib.parse import urlparse
import re
import ipaddress

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="PhishGuard | URL Detector",
    page_icon="🛡️",
    layout="centered"
)

# ---------------- CUSTOM DESIGN ----------------
st.markdown("""
<style>
.stApp {
    background: linear-gradient(135deg, #08111f, #10243a);
    color: #f1f5f9;
}
.block-container {
    max-width: 850px;
    padding-top: 2rem;
}
.hero {
    text-align: center;
    padding: 25px 10px;
}
.hero h1 {
    color: #38bdf8;
    font-size: 42px;
    margin-bottom: 5px;
}
.hero p {
    color: #cbd5e1;
    font-size: 17px;
}
.info-card {
    background: #14283e;
    border: 1px solid #29445e;
    padding: 20px;
    border-radius: 15px;
    margin: 12px 0;
}
div.stButton > button {
    width: 100%;
    background: #0284c7;
    color: white;
    border: none;
    border-radius: 10px;
    padding: 12px;
    font-weight: bold;
}
div.stButton > button:hover {
    background: #0369a1;
    color: white;
}
footer {visibility: hidden;}
</style>
""", unsafe_allow_html=True)


# ---------------- URL DETECTION ----------------
def check_url(user_url):
    score = 0
    reasons = []

    user_url = user_url.strip()

    if not user_url:
        return None, []

    # Add a scheme if the user omitted it
    if "://" not in user_url:
        user_url = "https://" + user_url

    try:
        parsed = urlparse(user_url)
        hostname = parsed.hostname

        if parsed.scheme not in ("http", "https") or not hostname:
            return None, ["Please enter a valid HTTP/HTTPS URL."]

        hostname = hostname.lower()

        # 1. HTTPS check
        if parsed.scheme != "https":
            score += 1
            reasons.append("HTTPS is not used.")

        # 2. IP address in hostname
        try:
            ipaddress.ip_address(hostname)
            score += 2
            reasons.append("The website uses an IP address instead of a domain name.")
        except ValueError:
            pass

        # 3. Suspicious words
        suspicious_words = [
            "login", "verify", "verification", "password",
            "signin", "sign-in", "account", "banking",
            "secure", "update", "confirm", "wallet",
            "free-gift", "prize"
        ]

        text_to_check = (hostname + parsed.path + parsed.query).lower()
        found_words = [
            word for word in suspicious_words
            if re.search(r"(?<![a-z])" + re.escape(word) + r"(?![a-z])",
                         text_to_check)
        ]

        if found_words:
            score += 1
            reasons.append(
                "Potentially suspicious keyword(s): "
                + ", ".join(found_words)
            )

        # 4. @ symbol
        if "@" in user_url:
            score += 2
            reasons.append("The URL contains an @ symbol.")

        # 5. Very long URL
        if len(user_url) > 100:
            score += 1
            reasons.append("The URL is unusually long.")

        # 6. Too many subdomains
        if len(hostname.split(".")) > 4:
            score += 1
            reasons.append("The domain has many subdomains.")

        # 7. Hyphens in hostname
        if hostname.count("-") >= 3:
            score += 1
            reasons.append("The domain contains multiple hyphens.")

        # 8. Punycode domain
        if "xn--" in hostname:
            score += 2
            reasons.append("The domain contains encoded international characters.")

        # 9. Unusual port
        try:
            port = parsed.port
            if port is not None and port not in (80, 443):
                score += 1
                reasons.append("The URL uses a non-standard port.")
        except ValueError:
            return None, ["The URL contains an invalid port."]

        # Results
        if score >= 3:
            status = "suspicious"
        elif score >= 1:
            status = "caution"
        else:
            status = "low_warning"

        return status, reasons

    except Exception:
        return None, ["Unable to parse this URL. Please check the format."]


# ---------------- WEBSITE HEADER ----------------
st.markdown("""
<div class="hero">
    <h1>🛡️ PhishGuard</h1>
    <p>Phishing URL Detection System</p>
    <p>Check suspicious links before you open them.</p>
</div>
""", unsafe_allow_html=True)

st.markdown("""
<div class="info-card">
<strong>🔍 How it works</strong><br>
Enter a website URL below. PhishGuard checks for common
warning signs such as suspicious keywords, unusual domains,
and missing HTTPS.
</div>
""", unsafe_allow_html=True)


# ---------------- INPUT FORM ----------------
with st.form("url_checker"):
    url = st.text_input(
        "🌐 Enter website URL",
        placeholder="https://example.com"
    )

    submitted = st.form_submit_button("🔎 Check URL")


# ---------------- SHOW RESULTS ----------------
if submitted:
    if not url.strip():
        st.warning("Please enter a URL first.")

    else:
        status, reasons = check_url(url)

        st.markdown("---")
        st.subheader("📊 Scan Results")

        if status is None:
            st.error("Invalid URL")
            for reason in reasons:
                st.write("•", reason)

        elif status == "suspicious":
            st.error("🚨 Potentially Suspicious URL")
            st.write(
                "This URL has multiple warning signs. "
                "Avoid entering passwords or personal information."
            )

        elif status == "caution":
            st.warning("⚠️ Caution: Warning Signs Found")
            st.write(
                "Some characteristics need further verification."
            )

        else:
            st.success("✅ No Obvious Warning Signs Detected")
            st.write(
                "This basic scan did not find the warning signs "
                "checked by this program."
            )

        if reasons:
            st.markdown("### ⚠️ Detected Warning Signs")
            for reason in reasons:
                st.write("•", reason)
        elif status is not None:
            st.info("No warning signs from the checks above were detected.")

        st.caption(
            "Note: This is a basic rule-based detector, not a "
            "guaranteed phishing classifier. A URL may still be "
            "malicious even if no warning is detected."
        )


# ---------------- FOOTER ----------------
st.markdown("---")
st.markdown(
    "<p style='text-align:center;color:#94a3b8;'>"
    "PhishGuard | Cyber Security Student Project"
    "</p>",
    unsafe_allow_html=True
)