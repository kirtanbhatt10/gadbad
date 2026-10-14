"""Detection rules: severity, score weight and plain-language explanations.

Explanations are written for the person who received the APK, not for analysts,
in English ("en") and Hindi ("hi").
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str  # "low", "medium" or "high"
    weight: int
    title: str
    en: str
    hi: str


RULES: dict[str, Rule] = {r.id: r for r in [
    Rule("not_apk", "medium", 30, "Not a valid APK",
         "This file is not a real Android app package.",
         "यह फ़ाइल असली Android ऐप पैकेज नहीं है।"),
    Rule("bad_manifest", "medium", 15, "Damaged or hidden manifest",
         "The app's manifest is damaged or hidden, a trick used to break analysis tools.",
         "ऐप का मैनिफ़ेस्ट खराब या छिपाया गया है, जो विश्लेषण टूल को चकमा देने की एक तरकीब है।"),
    Rule("sms_read", "high", 30, "Reads SMS",
         "Can read your SMS messages, including bank OTPs.",
         "यह ऐप आपके SMS पढ़ सकता है, जिनमें बैंक के OTP भी शामिल हैं।"),
    Rule("sms_receiver", "high", 25, "Listens for incoming SMS",
         "Wakes up the moment an SMS arrives, so it can grab OTPs as they come in.",
         "SMS आते ही यह ऐप सक्रिय हो जाता है, ताकि OTP तुरंत पकड़ सके।"),
    Rule("sms_send", "medium", 15, "Sends SMS",
         "Can send SMS from your number without asking.",
         "यह ऐप बिना पूछे आपके नंबर से SMS भेज सकता है।"),
    Rule("call_forwarding", "high", 25, "Call-forwarding code",
         "Contains a call-forwarding code (*21*) that can divert your calls, including bank verification calls.",
         "इसमें कॉल फ़ॉरवर्डिंग कोड (*21*) है, जिससे बैंक की वेरिफ़िकेशन कॉल समेत आपकी कॉल किसी और नंबर पर जा सकती हैं।"),
    Rule("accessibility", "high", 25, "Accessibility service",
         "Asks for Accessibility access, which lets it read your screen and tap buttons for you.",
         "यह Accessibility अनुमति माँगता है, जिससे यह आपकी स्क्रीन पढ़ सकता है और आपकी जगह बटन दबा सकता है।"),
    Rule("device_admin", "medium", 15, "Device administrator",
         "Can make itself a device administrator, which makes it hard to uninstall.",
         "यह खुद को डिवाइस एडमिन बना सकता है, जिससे इसे हटाना मुश्किल हो जाता है।"),
    Rule("overlay", "medium", 10, "Draws over other apps",
         "Can draw over other apps, a trick used to show fake login screens.",
         "यह दूसरे ऐप्स के ऊपर स्क्रीन दिखा सकता है, जिससे नकली लॉगिन पेज दिखाए जाते हैं।"),
    Rule("installs_apps", "medium", 10, "Installs other apps",
         "Can install other apps, so it may download more malware.",
         "यह दूसरे ऐप इंस्टॉल कर सकता है, यानी और मैलवेयर डाउनलोड कर सकता है।"),
    Rule("contacts", "low", 5, "Reads contacts",
         "Can read your contacts, often to send the same scam to them.",
         "यह आपके कॉन्टैक्ट पढ़ सकता है, अक्सर यही स्कैम उन्हें भेजने के लिए।"),
    Rule("autostart", "low", 5, "Starts on boot",
         "Starts automatically when the phone restarts.",
         "फ़ोन रीस्टार्ट होने पर यह अपने आप चालू हो जाता है।"),
    Rule("telegram_token", "high", 30, "Hardcoded Telegram bot token",
         "Contains a Telegram bot token, a common way to send stolen data to the attacker.",
         "इसमें Telegram बॉट टोकन है, जिसका इस्तेमाल अक्सर चोरी किया गया डेटा अपराधी तक भेजने में होता है।"),
    Rule("telegram_api", "medium", 15, "Talks to Telegram bot API",
         "Connects directly to the Telegram bot API.",
         "यह सीधे Telegram बॉट API से जुड़ता है।"),
    Rule("firebase", "medium", 10, "Firebase database endpoint",
         "Sends data to a Firebase database, a common drop point for stolen SMS.",
         "यह डेटा Firebase डेटाबेस में भेजता है, जहाँ अक्सर चोरी किए गए SMS जमा किए जाते हैं।"),
    Rule("ip_endpoint", "medium", 15, "Server addressed by raw IP",
         "Connects to a server by raw IP address instead of a domain name.",
         "यह डोमेन नाम की जगह सीधे IP पते वाले सर्वर से जुड़ता है।"),
    Rule("cleartext", "low", 5, "Allows unencrypted traffic",
         "Allows unencrypted HTTP traffic.",
         "यह बिना एन्क्रिप्शन वाला HTTP ट्रैफ़िक इस्तेमाल करता है।"),
    Rule("impersonation", "high", 20, "Impersonates a bank or government service",
         "Uses the name of a bank or government service while also reading SMS.",
         "यह किसी बैंक या सरकारी सेवा का नाम इस्तेमाल करता है और साथ ही SMS भी पढ़ता है।"),
]}

VERDICTS = [
    # (minimum score, verdict)
    (60, "likely malicious"),
    (25, "suspicious"),
    (1, "low risk"),
    (0, "no indicators found"),
]

ADVICE = {
    "likely malicious": {
        "en": "Do not install this app. If you already did: switch on flight mode, uninstall it, "
              "call your bank to block your cards and UPI, change banking passwords from another device, "
              "and report it at cybercrime.gov.in or by calling 1930.",
        "hi": "यह ऐप इंस्टॉल न करें। अगर कर लिया है: फ़्लाइट मोड चालू करें, ऐप हटाएँ, "
              "अपने बैंक को कॉल करके कार्ड और UPI ब्लॉक कराएँ, किसी दूसरे डिवाइस से बैंकिंग पासवर्ड बदलें, "
              "और cybercrime.gov.in पर शिकायत करें या 1930 पर कॉल करें।",
    },
    "suspicious": {
        "en": "Treat this app as unsafe. Only install apps from the Play Store, and never from a WhatsApp or SMS link.",
        "hi": "इस ऐप को असुरक्षित मानें। ऐप सिर्फ़ Play Store से इंस्टॉल करें, WhatsApp या SMS लिंक से कभी नहीं।",
    },
    "low risk": {
        "en": "No strong signs of fraud, but only install apps from the Play Store.",
        "hi": "धोखाधड़ी के पक्के संकेत नहीं मिले, फिर भी ऐप सिर्फ़ Play Store से इंस्टॉल करें।",
    },
    "no indicators found": {
        "en": "No known scam indicators were found. This is not a guarantee that the app is safe.",
        "hi": "कोई जाना-पहचाना स्कैम संकेत नहीं मिला। इसका मतलब यह नहीं कि ऐप पूरी तरह सुरक्षित है।",
    },
}


def verdict_for(score: int) -> str:
    for minimum, verdict in VERDICTS:
        if score >= minimum:
            return verdict
    return "no indicators found"
