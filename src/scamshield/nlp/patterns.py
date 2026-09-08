"""Multilingual keyword / pattern dictionaries for the ScamShield message engine.

This is an *initial, heuristic* multilingual support layer. It does NOT claim full
language understanding. It works by matching normalized tokens and short phrase
patterns across English, Hindi, Marathi and Hinglish (code-mixed) input.

Normalization strategy
----------------------
Tokens are lowercased and trimmed. For scripts written in Latin (English and
Roman-script Hinglish) we match on Roman tokens. For Devanagari (Hindi/Marathi)
we match on the Unicode Devanagari tokens directly. Because Hinglish is highly
code-mixed and romanised in many ways, we also include common romanised
variants (e.g. "jaldi", "abhi", "turanT") in the dictionaries.

A message is only flagged when a scored detection fires. Mere mention of a word
like "OTP", "bank", "KYC" or "payment" is NOT enough to call something a scam:
scoring combines multiple weighted indicators (see scoring.py).
"""

# ---------------------------------------------------------------------------
# Urgency / pressure language (contributes to "urgency" indicator)
# ---------------------------------------------------------------------------
URGENCY_WORDS: tuple[str, ...] = (
    "urgent", "immediately", "immediate", "act now", "right now", "asap",
    "hurry", "today only", "before today", "within 10 minutes", "before it's too late",
    "jaldi", "turant", "abhi", "foran", "expires", "expired", "last chance",
    "final notice", "will be blocked", "will be closed", "will be frozen",
    "don't miss", "act fast", "now or never",
    # Hindi / Marathi
    "तुरंत", "जल्दी", "अभी", "तुरन्त", "फौरन", "जल्द से जल्द", "आज ही",
    # romanised hindi/marathi
    "foran kare", "jaldi kare", "abhi kare", "jald se jald", "hone se pehle",
    "se pehle",
)

# ---------------------------------------------------------------------------
# Threats / account blocking (contributes to "threat")
# ---------------------------------------------------------------------------
THREAT_WORDS: tuple[str, ...] = (
    "account will be blocked", "account will be closed", "account will be frozen",
    "account blocked", "account closed", "account deactivated", "account suspended",
    "account terminated", "access will be lost", "will be locked", "will be banned",
    "will be deleted", "blocked permanently", "legal action", "arrest", "fine imposed",
    "court summons", "criminal", "lose your account", "services will be stopped",
    "card blocked", "card deactivated", "sim blocked", "likuidated account",
    "your account will be", "unit will be cut", "electricity will be cut",
    # Hindi / Marathi / romanised
    "खाता बंद", "खाता ब्लॉक", "खाता ब्लॉक हो", "खाता बंद हो", "ब्लॉक हो जाएगा",
    "बंद हो जाएगा", "गिरफ्तारी", "कानूनी कार्रवाई", "सिम ब्लॉक", "कट जाएगी",
    "अकाउंट ब्लॉक", "अकाउंट बंद", "खाते ब्लॉक होणार", "खाते ब्लॉक होईल",
    "ब्लॉक होणार आहे", "बँक खाते ब्लॉक", "account block ho", "account band ho",
    "account freeze ho", "account close ho", "sim block ho", "bijli cut",
    "card block ho", "account block hone", "block hone", "block hone se pehle",
    "account band hone", "hone se pehle", "disconnection", "will be disconnected",
    "power cut", "avoid disconnection", "cut off", "service will be cut",
    "will be stopped", "disconnected",
)

# ---------------------------------------------------------------------------
# Fake KYC / identity verification (contributes to "kyc_request")
# ---------------------------------------------------------------------------
KYC_WORDS: tuple[str, ...] = (
    "kyc", "know your customer", "e-kyc", "video kyc", "kyc update",
    "kyc expire", "kyc expired", "kyc pending", "kyc blocked", "re-kyc",
    "aadhaar", "aadhar", "pan update", "pan card", "verify identity",
    "identity verification", "re-verify", "revid", "reverification",
    # Hindi / Marathi
    "केवाईसी", "केवाएसी", "आधार", "पैन कार्ड", "पहचान सत्यापन", "फिर से सत्यापन",
    # romanised
    "aadhaar verify", "kyc karo", "kyc update karo", "apan update", "kyc do",
)

# ---------------------------------------------------------------------------
# OTP requests (contributes to "otp_request")
# ---------------------------------------------------------------------------
OTP_WORDS: tuple[str, ...] = (
    "otp", "one time password", "one-time password", "security code", "verification code",
    "otp share", "share otp", "send otp", "tell otp", "enter otp",
    # Hindi / Marathi
    "ओटीपी", "वन टाइम पासवर्ड", "सुरक्षा कोड", "सत्यापन कोड", "ओटीपी दें",
    "ओटीपी बताएं", "ओटीपी भेजें", "ओटीपी शेयर", "प्रमाणीकरण कोड",
    # romanised
    "otp batao", "otp do", "otp share karo", "otp bhejo", "otp maango",
    "otp bata", "otp dene", "otp de",
)

# ---------------------------------------------------------------------------
# PIN / password / card details requests (contributes to "credential_request")
# ---------------------------------------------------------------------------
CREDENTIAL_WORDS: tuple[str, ...] = (
    "pin", "upi pin", "atm pin", "password", "card number", "card no",
    "card details", "cvv", "cvv2", "credit card number", "debit card number",
    "netbanking password", "login password", "bank password",
    "share pin", "share password", "tell pin", "verify pin", "enter pin",
    "enter password", "confirm pin", "bank details", "account number",
    "share your pin", "give your pin", "provide pin", "tell your cvv",
    # Hindi / Marathi
    "पिन", "यूपीआई पिन", "एटीएम पिन", "पासवर्ड", "कार्ड नंबर", "सीवीवी",
    "नेटबैंकिंग पासवर्ड", "खाता नंबर", "पिन बताएं", "पासवर्ड बताएं",
    "पिन दें", "पासवर्ड शेयर", "पिन शेयर",
    # romanised
    "pin batao", "pin do", "pin share karo", "password batao", "pin bata",
    "cvv do", "bank details do",
)

# ---------------------------------------------------------------------------
# UPI / payment / money transfer requests (contributes to "upi_payment_request")
# ---------------------------------------------------------------------------
UPI_PAYMENT_WORDS: tuple[str, ...] = (
    "upi", "phonepe", "google pay", "gpay", "paytm", "bhim", "upi collect",
    "collect request", "payment request", "refund", "cashback", "money transfer",
    "send money", "transfer money", "pay now", "pay the remaining", "pay fee",
    "processing fee", "registration fee", "register fee", "registration charges", "security deposit",
    "advance payment", "pay gst", "pay tax", "pay customs", "pay extra",
    "pay the extra", "pay the remaining", "pay the", "delivery charge",
    "extra delivery charge", "credit your wallet", "receive pwqr", "collect cashback",
    "claim refund", "pay the amount", "pay rs", "pay rupees", "send payment", "upi pay",
    "approve the request", "approve payment", "confirm payment", "refund pending",
    # Hindi / Marathi
    "यूपीआई", "फोनपे", "जीपे", "पेटीएम", "भीम", "रिफंड", "कैशबैक", "पैसे भेजें",
    "पैसे ट्रांसफर", "प्रोसेसिंग फीस", "रजिस्ट्रेशन फीस", "सिक्योरिटी डिपॉज़िट",
    "जीएसटी भरें", "टैक्स भरें", "कस्टम्स भरें", "पैसे काटे", "पेमेंट कन्फर्म",
    "पैसे भेजो", "रुपये भेजें", "पेमेंट", "फीस भरें", "फी भरा",
    "बिल भरा", "बिल भरें",
    # romanised
    "paise bhejo", "paise bhej", "rupaye bhejo", "upi pay karo", "paisa bhejo",
    "pay karo", "processing fee do", "fee bharo", "gst bharo", "refund do",
    "upi pe bhejo", "money bhejo", "payment karo", "pay karke", "pay kare",
)

# ---------------------------------------------------------------------------
# Prize / lottery claims (contributes to "prize_lottery")
# ---------------------------------------------------------------------------
PRIZE_WORDS: tuple[str, ...] = (
    "you won", "you have won", "you are the winner", "lucky draw", "lottery",
    "prize", "congratulations you won", "mega win", "winner", "jackpot",
    "win a prize", "you are selected", "claim your prize", "gift voucher",
    "free iphone", "won a prize of", "prize of rs", "kbc", "contest winner",
    # Hindi / Marathi
    "जीते", "जीत गए", "लॉटरी", "प्राइज़", "इनाम", "लकी ड्रॉ", "विजेता",
    "इनाम मिला", "पुरस्कार", "बक्षीस", "जिंकली", "जिंकलात", "जिंकले",
    "जिंकला", "मिळाले", "मिळालं",
    # romanised
    "jeete ho", "jeet gaye", "lucky draw winner", "winner ho", "laat lag gayi",
    "inkaam mila", "jiti", "jeete hai", "jeete", "25 lakh jeete", "aap jeete",
    "jeeta hai",
)

# ---------------------------------------------------------------------------
# Fake job offers (contributes to "job_offer")
# ---------------------------------------------------------------------------
JOB_WORDS: tuple[str, ...] = (
    "work from home", "wfh", "part time job", "part-time job", "data entry job",
    "job offer", "job selected", "job confirmation", "registration fee", "security fee",
    "register fee", "no experience needed", "no experience",
    "work from home job", "daily payment", "earn from home", "part time",
    "data entry", "job se mila", "online job", "work from home opportunity",
    # Hindi / Marathi
    "घर बैठे नौकरी", "डेटा एंट्री", "पार्ट टाइम", "नौकरी", "रजिस्ट्रेशन फीस",
    "डेटा एंट्री जॉब", "ऑनलाइन जॉब", "घर से काम", "नौकरी मिली", "नोकरी",
    "घरून काम", "भरती", "रजिस्ट्रेशन फी", "सुरक्षा ठेव", "घरून जॉब",
    "घर बसून नोकरी", "दिवसाला", "ऑफिस नोकरी",
    # romanised
    "wfh job", "ghar baithe naukari", "data entry job", "naukari mili",
    "registration fee do", "job ke liye", "part time job mili", "ghar se kaam",
)

# ---------------------------------------------------------------------------
# Investment / guaranteed returns (contributes to "investment_offer")
# ---------------------------------------------------------------------------
INVESTMENT_WORDS: tuple[str, ...] = (
    "double your money", "guaranteed return", "guaranteed profit", "profit sharing",
    "high return", "investment", "stock tip", "trading group", "crypto",
    "cryptocurrency", "bitcoin", "wealth creation", "passive income", "multiply",
    "2% daily", "100% profit", "sure shot", "no risk investment", "guaranteed",
    "tesla shares", "invest rs", "invest now", "high profit", "money double",
    # Hindi / Marathi
    "पैसा डबल", "गारंटी मुनाफा", "गारंटी रिटर्न", "निवेश", "क्रिप्टो",
    "स्टॉक टिप", "शेयर", "रिस्क फ्री", "पैसा दोगुना", "लाभ", "नफा",
    "मुनाफा", "दुबले", "गुंतवणूक", "हमी रिटर्न",
    # romanised
    "paisa double", "guaranteed profit", "investment plan", "crypto me",
    "stock tip do", "munaafa", "lagaa lagaa", "paisa lagao", "invest karo",
    "dona", "share me",
)

# ---------------------------------------------------------------------------
# Fake loan offers (contributes to "loan_offer")
# ---------------------------------------------------------------------------
LOAN_WORDS: tuple[str, ...] = (
    "loan", "instant loan", "personal loan", "pre-approved loan", "pre-approved",
    "loan approved", "loan sanctioned", "loan disbursed", "loan offer",
    "no documents loan", "processing fee", "processing charges",
    "loan processing", "loan release", "loan given",
    "credit loan", "borrow money", "take loan", "loan application",
    "first pay gst", "insurance premium", "loan fee", "loan avilable",
    # Hindi / Marathi
    "लोन", "कर्ज", "इंस्टेंट लोन", "लोन मंजूर", "कर्ज मंजूर", "प्रोसेसिंग फीस",
    "ऋण", "लोन दिया", "बिना कागज़ लोन", "व्याज", "लोन मिलेगा",
    # romanised
    "loan mila", "instant loan", "loan approve", "loan do", "karg",
    "karj mila", "loan release", "loan fee",
)

# ---------------------------------------------------------------------------
# Fake customer care / support (contributes to "customer_care")
# ---------------------------------------------------------------------------
CUSTOMER_CARE_WORDS: tuple[str, ...] = (
    "customer care", "helpline", "support", "helpdesk", "technical support",
    "official helpline", "call this number", "press 1", "our support",
    "customer service", "care partner", "verify your card", "support team",
    "service desk", "call us", "customer care number",
    # Hindi / Marathi
    "कस्टमर केयर", "हेल्पलाइन", "सहायता", "टेक्निकल सपोर्ट", "ग्राहक सेवा",
    "सपोर्ट", "ग्राहक केयर", "हमारी सहायता",
    # romanised
    "customer care", "helpline", "support", "call karo", "customer care bol",
    "sahayata",
)

# ---------------------------------------------------------------------------
# Delivery / courier / parcel scams (contributes to "delivery_package")
# ---------------------------------------------------------------------------
DELIVERY_WORDS: tuple[str, ...] = (
    "parcel", "courier", "customs", "delivery", "package", "shipment",
    "stuck in customs", "customs clearance", "delivery fee", "freight",
    "parcel held", "package held", "address incomplete", "avelivery charges",
    "package is stuck", "parcel is stuck", "extra charges", "cash on delivery",
    "import duty", "custom duty",
    # Hindi / Marathi
    "पार्सल", "कूरियर", "कस्टम", "डिलीवरी", "पैकेज", "शुल्क", "भाड़ा",
    "माल", "पार्सल अटका", "डिलीवरी चार्ज", "एक्स्ट्रा चार्ज",
    # romanised
    "parcel atka", "parcel do", "courier wala", "delivery charge", "parcel stuck",
    "customs me atka", "parcel pay",
)

# ---------------------------------------------------------------------------
# Bank impersonation (contributes to "bank_impersonation")
# ---------------------------------------------------------------------------
BANK_WORDS: tuple[str, ...] = (
    "sbi", "hdfc", "icici", "axis bank", "pnb", "bank of baroda", "yes bank",
    "karnataka bank", "union bank", "canara bank", "bank", "your bank",
    "bank account", "banking", "netbanking", "debit card", "credit card",
    "atm card", "bank official", "this is bank", "bank helpline",
    # Hindi / Marathi
    "बैंक", "एटीएम कार्ड", "डेबिट कार्ड", "क्रेडिट कार्ड", "बैंक खाता",
    "नेटबैंकिंग", "बैंक अधिकारी", "बैंक कर्मचारी", "बँक", "बँक खाते",
    "बँक अधिकृत", "बँक कर्मचारी",
    # romanised
    "bank account", "atm card", "bank official", "bank bol", "bank employee",
    "bank ka", "bank se",
)

# ---------------------------------------------------------------------------
# Government impersonation (contributes to "government_impersonation")
# ---------------------------------------------------------------------------
GOVERNMENT_WORDS: tuple[str, ...] = (
    "income tax", "itr", "tax refund", "government", "govt", "trai", "sim card",
    "electricity board", "power bill", "court", "court summons", "legal department",
    "cyber cell", "police", "income tax department", "aadhaar suspended",
    "aadhaar is suspended", "tax department", "revenue department", "subsidy",
    "railway", "irctc", "passport", "gas agency", "ration card",
    # Hindi / Marathi
    "आयकर", "आईटीआर", "सरकार", "अदालत", "पुलिस", "बिजली", "वीज", "कचरा",
    "सब्सिडी", "पासपोर्ट", "राशन कार्ड", "कोर्ट", "ट्राई", "सिम",
    "बिजली बिल", "वीज बिल", "बिजली कट",
    # romanised
    "income tax", "itr", "sarkar", "government", "court", "police", "bijli",
    "sim block", "adhar suspend", "electricity", "electricity bill", "power bill",
    "utility", "disconnection",
)

# ---------------------------------------------------------------------------
# Social media / account impersonation (contributes to "social_impersonation")
# ---------------------------------------------------------------------------
SOCIAL_WORDS: tuple[str, ...] = (
    "instagram", "facebook", "whatsapp", "gmail", "google account", "email account",
    "your account", "account deleted", "account suspended", "account hacked",
    "verify your account", "account will be deleted", "account recovery",
    "send money", "emergency", "my phone broke", "my phone is broken", "relative",
    "your son", "your brother", "your sister", "your friend", "i am your",
    "transfer immediately", "victim of", "phone lost", "wallet stolen",
    # Hindi / Marathi
    "इंस्टाग्राम", "फेसबुक", "व्हाट्सएप", "अकाउंट", "मेरा फोन", "मेरा भाई",
    "तुम्हारा भाई", "भाई फोन", "मित्र", "खाता हैक", "खाता डिलीट",
    # romanised
    "account delete", "account hack", "mera bhai", "tumhara bhai", "phone chala",
    "friend", "emergency hai", "bhai phone", "account recovery", "login karo",
    "verify account",
)

# ---------------------------------------------------------------------------
# Requests for sensitive / personal information (contributes to "sensitive_info_request")
# ---------------------------------------------------------------------------
SENSITIVE_INFO_WORDS: tuple[str, ...] = (
    "share otp", "share pin", "share password", "share bank details",
    "share aadhaar", "share pan", "send aadhaar", "send pan", "send otp",
    "confirm pin", "tell pan", "tell aadhaar", "give berth", "provide details",
    "send your documents", "share your documents", "account details", "upi id",
    "bank details", "passbook photo", "aadhaar photo", "your details",
    "doctr", "verify aadhaar", "share your card", "give your card", "card details",
    # Hindi / Marathi
    "आधार भेजें", "पैन भेजें", "बैंक डिटेल्स", "दस्तावेज़ भेजें", "फोटो भेजें",
    "पासबुक", "आधार फोटो", "जानकारी दें", "विवरण दें",
    # romanised
    "details bhejo", "bank details bhejo", "aadhaar bhejo", "pan bhejo",
    "documents bhejo", "details do", "document bhejo", "photos bhejo",
)

# ---------------------------------------------------------------------------
# Suspicious / branded link language (contributes to "suspicious_link_hint")
# ---------------------------------------------------------------------------
LINK_HINT_WORDS: tuple[str, ...] = (
    "click", "click here", "tap here", "open the link", "open link",
    "go to", "sign in", "type the url", "copy the link", "follow the link",
    "see the link", "verify at", "update at", "reset here", "check here",
    "this link", "the link", "below link", "given link", "shared link",
    "click on the link", "open this link", "this web", "web link",
    # Hindi / Marathi
    "क्लिक करें", "लिंक खोलें", "यहाँ जाएं", "वेरिफाई करें", "अपडेट करें",
    "लिंक खोलो", "क्लिक करो", "यहां क्लिक", "लिंक पर जाएं", "यह लिंक",
    "लिंक उघडा", "उघडा", "क्लिक करा", "लिंक उघडून",
    # romanised
    "click karo", "link kholo", "link khol", "yahan jao", "link pe jao",
    "visit karo", "open the link", "link open do", "ye link", "is link",
    "link pe", "link open karo", "link open", "link open kare", "link khol do",
)

# ---------------------------------------------------------------------------
# Legitimate / safe cues. A message is DOWN-weighted (made less likely to be a
# scam) if it clearly comes from a legitimate channel and does not request
# credentials / money. These are protective cues.
# ---------------------------------------------------------------------------
SAFE_MARKERS: tuple[str, ...] = (
    "do not share otp", "never share otp", "do not share your otp",
    "never share your otp", "official app", "official bank app", "official website",
    "bank will never ask", "bank never asks", "do not share", "never share",
    "ignore such", "ignore any", "safe to ignore", "fraud alert", "beware of fraud",
    "don't share", "ignore", "official app only", "do not click on any link",
    "dispute ke liye official app use karo", "official app use karo",
    # Hindi / Marathi
    "ओटीपी किसी को न दें", "ओटीपी साझा न करें", "अधिकारिक ऐप", "कोई लिंक नहीं",
    "किसी को न दें", "साझा न करें", "आधिकारिक वेबसाइट", "कोई लिंक नहीं है",
    "अधिकृत अॅप", "सावधान", "धोखाधड़ी", "लिंक नहीं", "लिंक न खोलें",
    # romanised
    "otp kisi ko mat dena", "otp share mat karna", "official app", "koi link nahi",
    "mat dena", "share mat karna", "link nahi", "link mat kholna",
    "official app se", "official app se hi", "official app use karo",
    "kowi link nahi hai", "official website",
)

# ---------------------------------------------------------------------------
# Intentional reward / money-out-of-state claims frequently tied to scams
# ---------------------------------------------------------------------------
REWARD_CLAIM_WORDS: tuple[str, ...] = (
    "25 lakh", "rs 25 lakh", "prize of rs", "won rs", "you received",
    "received rs", "credited to", "credited rs", "you have received",
    "wallet credited", "cashback of", "refund of",
)
