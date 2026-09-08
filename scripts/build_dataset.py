"""Build the Step 2 labelled dataset: synthetic Indian/Hinglish examples + optional public rows.

Run from the repo root:
    python scripts/build_dataset.py
"""

from __future__ import annotations

import csv
import json
import random
import re
from collections import defaultdict
from itertools import product
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
RAW_HF = DATA / "raw" / "ultra_premium_scam_dataset.csv"
SEED = 42

BANKS = ["SBI", "HDFC", "ICICI", "Axis", "PNB", "Bank of Baroda"]
URLS = [
    "http://verify-kyc.example.in/update",
    "http://192.0.2.10/login",
    "https://bit.ly/exkyc99",
    "http://secure-upi.example.in/pay",
]
APPS = ["PhonePe", "Google Pay", "Paytm", "BHIM"]

PHONE_RE = re.compile(r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)")
ACCOUNT_RE = re.compile(r"(?<!\d)\d{9,18}(?!\d)")


def sanitize(text: str) -> str:
    text = PHONE_RE.sub("[PHONE]", text)
    text = ACCOUNT_RE.sub("[ACCOUNT]", text)
    # Do not blank years/amounts: only standalone 4-8 digit tokens after phones/accounts.
    # Amounts use ₹ or Rs and are left intact. OTP-like "Your OTP is 123456" → placeholder.
    text = re.sub(
        r"(?i)(\bOTP\b[:\s]*)\d{4,8}",
        r"\1[OTP]",
        text,
    )
    return text.strip()


def row(text, language, label, scam_type, source, indicators):
    ind = indicators if isinstance(indicators, str) else "|".join(indicators)
    return {
        "text": sanitize(text),
        "language": language,
        "scam_or_safe": label,
        "scam_type": scam_type if label == "scam" else "safe",
        "source": source,
        "indicators": ind if label == "scam" else (ind if ind else "none"),
    }


def synthetic_scams() -> list[dict]:
    out: list[dict] = []
    src = "synthetic_scamshield"

    kyc = {
        "en": [
            "Dear customer, your {bank} KYC has expired. Click {url} immediately to prevent account blocking.",
            "Your {bank} KYC is pending. Update now at {url} or your account will be frozen today.",
            "Urgent: complete {bank} video KYC on {url} to keep UPI active.",
        ],
        "hi": [
            "आपका {bank} KYC समाप्त हो गया है। खाता बंद होने से पहले {url} पर अपडेट करें।",
            "तुरंत {bank} केवाईसी पूरा करें वरना आपका खाता ब्लॉक हो जाएगा {url}",
        ],
        "mr": [
            "तुमचे {bank} KYC कालबाह्य झाले आहे. खाते ब्लॉक होण्यापूर्वी {url} उघडा.",
            "{bank} व्हिडिओ केवायसी {url} वर पूर्ण करा, नाहीतर यूपीआय बंद होईल.",
        ],
        "hinglish": [
            "Aapka {bank} KYC expire ho gaya hai, account block hone se pehle link open karo {url}.",
            "{bank} KYC pending hai. Jaldi {url} pe update karo warna account band ho jayega.",
            "Aapka KYC expire ho gaya hai, turant link kholo {url} nahi to banking ruk jayegi.",
        ],
    }
    for lang, templates in kyc.items():
        for tmpl, bank, url in product(templates, BANKS[:4], URLS[:2]):
            out.append(
                row(
                    tmpl.format(bank=bank, url=url),
                    lang,
                    "scam",
                    "kyc",
                    src,
                    "urgency|kyc_language|account_block_threat|suspicious_url",
                )
            )

    upi = {
        "en": [
            "Your {app} payment of Rs 1 failed. Pay the remaining Rs 1 on {url} to receive a refund.",
            "You received Rs 50,000. Confirm UPI PIN on {url} to credit your {app} wallet.",
            "Collect cashback on {app}: enter UPI PIN at {url} now.",
        ],
        "hi": [
            "आपको {app} पर ₹25000 मिले हैं। क्रेडिट के लिए UPI पिन {url} पर दर्ज करें।",
            "{app} रिफंड अटका है। {url} पर पिन डालकर पाएं।",
        ],
        "mr": [
            "{app} वर पैसे अडकले आहेत. UPI पिन {url} वर टाका.",
            "रिफंड मिळवण्यासाठी {url} वर पेमेंट कन्फर्म करा.",
        ],
        "hinglish": [
            "{app} se refund aaya hai, UPI PIN {url} pe daalo warna cancel ho jayega.",
            "Aapke account me 1 rupee pending hai {app}. {url} pe pay karke 25000 claim karo.",
            "UPI collect request approve karo {url} pe, warna paise kat jayenge.",
        ],
    }
    for lang, templates in upi.items():
        for tmpl, app, url in product(templates, APPS[:3], URLS[:2]):
            out.append(
                row(
                    tmpl.format(app=app, url=url),
                    lang,
                    "scam",
                    "upi_payment",
                    src,
                    "payment_request|otp_request|suspicious_url|urgency",
                )
            )

    bank_imp = {
        "en": [
            "Your {bank} debit card is blocked. Share OTP and login at {url} to unblock.",
            "{bank} security: unusual login detected. Confirm PIN on {url} within 10 minutes.",
            "This is {bank} official. Your account will be closed. Call and share OTP now.",
        ],
        "hi": [
            "{bank} खाता संदिग्ध गतिविधि के कारण बंद होगा। {url} पर OTP डालें।",
            "आपका {bank} कार्ड ब्लॉक है। अनब्लॉक करने हेतु {url} खोलें।",
        ],
        "mr": [
            "{bank} खाते ब्लॉक होणार आहे. OTP {url} वर द्या.",
            "{bank} अधिकृत संदेश: पिन शेअर करा आणि {url} उघडा.",
        ],
        "hinglish": [
            "Aapka {bank} account block ho raha hai. OTP share karo aur {url} kholo.",
            "{bank} se call aayega mat sochna, ATM PIN bata dena. Pehle {url} pe verify karo.",
            "Aapka {bank} ATM card block ho gaya hai, details update kare {url}",
        ],
    }
    for lang, templates in bank_imp.items():
        for tmpl, bank, url in product(templates, BANKS[:4], URLS[:2]):
            out.append(
                row(
                    tmpl.format(bank=bank, url=url),
                    lang,
                    "scam",
                    "bank_impersonation",
                    src,
                    "bank_impersonation|otp_request|urgency|suspicious_url",
                )
            )

    phishing = {
        "en": [
            "Reset your email password here {url} or access will be lost today.",
            "Income tax refund pending. Submit PAN on {url} immediately.",
            "Your Aadhaar is suspended. Re-verify at {url}.",
        ],
        "hi": [
            "आपका ईमेल हैंग हो गया है। {url} पर पासवर्ड रीसेट करें।",
            "आयकर रिफंड {url} पर क्लेम करें, तुरंत PAN डालें।",
        ],
        "mr": [
            "तुमचे आधार निलंबित. {url} वर पुन्हा पडताळणी करा.",
            "ईमेल लॉगिन {url} वर अपडेट करा नाहीतर बंद होईल.",
        ],
        "hinglish": [
            "Aapka email hack ho gaya, password {url} pe reset karo.",
            "ITR refund pending hai, PAN {url} pe submit karo jaldi.",
            "Aadhaar lock ho gaya hai, {url} pe verify karo warna subsidy ruk jayegi.",
        ],
    }
    for lang, templates in phishing.items():
        for tmpl, url in product(templates, URLS[:2]):
            out.append(
                row(
                    tmpl.format(url=url),
                    lang,
                    "scam",
                    "phishing",
                    src,
                    "suspicious_url|urgency|sensitive_info_request",
                )
            )

    care = {
        "en": [
            "Amazon customer care: your order failed. Call this number and share OTP.",
            "{bank} helpline: press 1 and tell us your CVV to verify the card.",
            "Paytm support: we are sending a request, approve it and read the OTP.",
        ],
        "hi": [
            "फ्लिपकार्ट केयर: ऑर्डर कैंसल। OTP बताइए।",
            "{bank} कस्टमर केयर से बात करें और पिन शेयर करें।",
        ],
        "mr": [
            "ग्राहक सेवा: ऑर्डर अडकला. OTP सांगा.",
            "{bank} हेल्पलाइन: CVV द्या म्हणजे कार्ड सुरू होईल.",
        ],
        "hinglish": [
            "Amazon customer care bol raha hoon, OTP batao order release hoga.",
            "{bank} helpline se call hai, ATM PIN verify karna hai abhi.",
            "Netflix support: payment fail, OTP share karo {url}",
        ],
    }
    for lang, templates in care.items():
        for tmpl, bank, url in product(templates, BANKS[:3], URLS[:2]):
            out.append(
                row(
                    tmpl.format(bank=bank, url=url),
                    lang,
                    "scam",
                    "customer_care",
                    src,
                    "customer_care|otp_request|bank_impersonation",
                )
            )

    jobs = {
        "en": [
            "Work from home: Rs 1500/day. Pay Rs 499 registration at {url}.",
            "Google is hiring data entry. WhatsApp your Aadhaar and bank details.",
            "Part time job selected. Deposit security fee on UPI to start.",
        ],
        "hi": [
            "घर बैठे नौकरी, रोज़ ₹2000। रजिस्ट्रेशन फीस {url} पर भेजें।",
            "डेटा एंट्री जॉब कन्फर्म। आधार और पासबुक फोटो भेजो।",
        ],
        "mr": [
            "घरून जॉब: दिवसाला ₹1800. फी {url} वर भरा.",
            "तुम्ही निवडले. सुरक्षा ठेव UPI ने पाठवा.",
        ],
        "hinglish": [
            "WFH job mili hai 1500 roz, pehle 499 {url} pe pay karo.",
            "Data entry job confirm, Aadhaar aur account number bhejo.",
            "Part time selected, security deposit UPI pe bhejna zaroori hai.",
        ],
    }
    for lang, templates in jobs.items():
        for tmpl, url in product(templates, URLS[:2]):
            out.append(
                row(
                    tmpl.format(url=url),
                    lang,
                    "scam",
                    "job",
                    src,
                    "job_offer|payment_request|sensitive_info_request",
                )
            )

    invest = {
        "en": [
            "Double your money in 24 hours with our crypto trading group. Deposit on {url}.",
            "Stock tip: guaranteed 40% return this week. Pay advisory fee now.",
            "Tesla profit sharing India. Invest Rs 5000 via UPI to join.",
        ],
        "hi": [
            "24 घंटे में पैसा डबल। {url} पर निवेश करें।",
            "शेयर में गारंटी मुनाफा। अभी UPI भेजें।",
        ],
        "mr": [
            "क्रिप्टो ग्रुप: 24 तासात डबल. {url} वर पैसे टाका.",
            "शेअर टिप गॅरंटी रिटर्न. UPI ने फी भरा.",
        ],
        "hinglish": [
            "Crypto me 24 ghante me double, {url} pe deposit karo.",
            "Stock tips guaranteed profit, advisory fee UPI pe bhejo.",
            "Investment plan 40 percent return, jaldi {url} pe join karo.",
        ],
    }
    for lang, templates in invest.items():
        for tmpl, url in product(templates, URLS[:2]):
            out.append(
                row(
                    tmpl.format(url=url),
                    lang,
                    "scam",
                    "investment",
                    src,
                    "investment_return|payment_request|urgency",
                )
            )

    loan = {
        "en": [
            "You are pre-approved for an instant loan. Click {url} and pay processing fee.",
            "No documents loan disbursed today. First pay GST on {url}.",
            "Your loan is sanctioned. Transfer insurance premium to release funds.",
        ],
        "hi": [
            "तुरंत लोन मंजूर। प्रोसेसिंग फीस {url} पर भेजें।",
            "बिना कागज़ लोन। पहले GST {url} पर चुकाएँ।",
        ],
        "mr": [
            "झटपट कर्ज मंजूर. फी {url} वर भरा.",
            "कर्ज रिलीज करण्यासाठी इन्शुरन्स प्रीमियम भरा.",
        ],
        "hinglish": [
            "Instant loan approve ho gaya, processing fee {url} pe do.",
            "Bina documents loan, pehle GST {url} pe pay karo.",
            "You are selected for instant loan approval, click to proceed {url}",
        ],
    }
    for lang, templates in loan.items():
        for tmpl, url in product(templates, URLS[:2]):
            out.append(
                row(
                    tmpl.format(url=url),
                    lang,
                    "scam",
                    "loan",
                    src,
                    "loan_offer|payment_request|suspicious_url|urgency",
                )
            )

    delivery = {
        "en": [
            "Your parcel is stuck in customs. Pay Rs 35 at {url} to release.",
            "Courier: address incomplete. Pay extra freight on {url} now.",
            "Package held at hub. Share OTP and pay cash-on-hold fee.",
        ],
        "hi": [
            "पार्सल कस्टम में अटका है। ₹35 {url} पर दें।",
            "कूरियर: अतिरिक्त शुल्क {url} पर चुकाएँ वरना वापस जाएगा।",
        ],
        "mr": [
            "पार्सल कस्टम्स मध्ये अडकले. ₹35 {url} वर भरा.",
            "पत्ता अपुरा. अतिरिक्त भाडे {url} वर द्या.",
        ],
        "hinglish": [
            "Aapka parcel customs me atka hai, Rs 35 pay karke release kare {url}",
            "Courier wala kehta hai extra charge {url} pe do warna return.",
            "Package hold pe hai, OTP do aur {url} pe fee bharo.",
        ],
    }
    for lang, templates in delivery.items():
        for tmpl, url in product(templates, URLS[:2]):
            out.append(
                row(
                    tmpl.format(url=url),
                    lang,
                    "scam",
                    "delivery",
                    src,
                    "delivery_threat|payment_request|suspicious_url",
                )
            )

    lottery = {
        "en": [
            "You won a KBC prize of Rs 25 lakh. Pay processing tax at {url}.",
            "Lucky draw winner. Share bank details and OTP to claim.",
            "Flipkart mega win. Pay Rs 99 delivery for your iPhone at {url}.",
        ],
        "hi": [
            "आपने केबीसी में ₹25 लाख जीते। टैक्स {url} पर भरें।",
            "लकी ड्रॉ विजेता। दावा करने के लिए OTP दें।",
        ],
        "mr": [
            "तुम्ही लॉटरी जिंकली. टॅक्स {url} वर भरा.",
            "बक्षीस मिळवण्यासाठी बँक डिटेल्स आणि OTP द्या.",
        ],
        "hinglish": [
            "KBC me 25 lakh jeete ho, processing tax {url} pe bharo.",
            "Lucky draw winner, bank details aur OTP share karo prize ke liye.",
            "iPhone free mila hai, Rs 99 {url} pe delivery fee do.",
        ],
    }
    for lang, templates in lottery.items():
        for tmpl, url in product(templates, URLS[:2]):
            out.append(
                row(
                    tmpl.format(url=url),
                    lang,
                    "scam",
                    "lottery",
                    src,
                    "prize_lottery|payment_request|urgency",
                )
            )

    social = {
        "en": [
            "Hi, this is your relative. My phone broke. Send Rs 5000 on this UPI now.",
            "I am your son. Emergency in college. Transfer to this QR immediately.",
            "Instagram: your account will be deleted. Login at {url} to verify.",
        ],
        "hi": [
            "मैं तुम्हारा भाई हूँ, फोन खो गया। इस UPI पर ₹3000 भेजो।",
            "इन्स्टाग्राम अकाउंट बंद होगा। {url} पर लॉगिन करो।",
        ],
        "mr": [
            "मी तुझा मित्र. वॉलेट चोरीला. या UPI वर पैसे पाठव.",
            "इंस्टा अकाउंट डिलीट होईल. {url} वर लॉगिन कर.",
        ],
        "hinglish": [
            "Bhai phone chala gaya, is UPI pe 4000 bhej de jaldi.",
            "Main tumhara beta bol raha hoon, emergency hai, QR pe paise bhejo.",
            "Instagram account delete ho raha hai, {url} pe login karke save karo.",
        ],
    }
    for lang, templates in social.items():
        for tmpl, url in product(templates, URLS[:2]):
            out.append(
                row(
                    tmpl.format(url=url),
                    lang,
                    "scam",
                    "social_impersonation",
                    src,
                    "social_impersonation|payment_request|urgency",
                )
            )

    other = {
        "en": [
            "Electricity will be cut in 2 hours. Pay pending bill only on {url}.",
            "Your SIM will be blocked under new TRAI rules. Recharge KYC at {url}.",
            "Court summons: settle fine online {url} to avoid arrest.",
        ],
        "hi": [
            "बिजली 2 घंटे में कटेगी। बिल {url} पर भरें।",
            "सिम ब्लॉक होगी। {url} पर केवाईसी करें।",
        ],
        "mr": [
            "वीज जोडणी तोडली जाईल. बिल {url} वर भरा.",
            "कोर्टाची नोटीस. दंड {url} वर भरा.",
        ],
        "hinglish": [
            "Bijli 2 ghante me cut hogi, bill sirf {url} pe bharo.",
            "SIM block ho jayegi TRAI ke hisaab se, {url} pe KYC karo.",
            "Court summons aaya hai, fine {url} pe bharo warna arrest.",
        ],
    }
    for lang, templates in other.items():
        for tmpl, url in product(templates, URLS[:2]):
            out.append(
                row(
                    tmpl.format(url=url),
                    lang,
                    "scam",
                    "other",
                    src,
                    "urgency|suspicious_url|impersonation",
                )
            )

    return out


def synthetic_safe() -> list[dict]:
    out: list[dict] = []
    src = "synthetic_scamshield"
    last4 = ["XX12", "XX47", "XX90", "XX33"]
    amounts = ["250.00", "1,200.50", "80.00", "3,499.00"]

    en = [
        "{bank}: Rs.{amt} credited to a/c {last4} on 06-Sep. Avl Bal Rs.5,000.00. Do not share OTP.",
        "{bank} OTP for login is [OTP]. Do not share with anyone.",
        "Your {app} payment of Rs.{amt} to Merchant is successful. UPI Ref [REF].",
        "Your Amazon order has been shipped. Track it in the official Amazon app.",
        "IRCTC: ticket booked successfully. Show this SMS at boarding.",
        "Thank you for your purchase. Invoice is in your registered email.",
        "Mum, I reached campus. Call you after class.",
        "Meeting moved to 4pm tomorrow in college lab.",
        "Your electricity bill of Rs.{amt} was paid via the official app.",
        "{bank}: EMI of Rs.{amt} auto-debited. No action needed.",
        "Library books are due Friday. Renew on the college portal.",
        "Your {app} cashback of Rs.10 is added. Check the official app.",
        "{bank} mini statement: last txn Rs.{amt} at grocery store.",
        "Doctor appointment confirmed for 11am. Please arrive 10 minutes early.",
        "Bus pass renewed. Show this SMS to the conductor if asked.",
        "WiFi password was reset by the hostel office. Ask the warden, not a link.",
        "Salary for August credited. Download payslip from the HR portal.",
        "Your FASTag was recharged Rs.{amt} from linked {bank} account.",
        "Class cancelled due to rain. Next lecture on Monday.",
        "Happy birthday! Dinner at home tonight, no need to transfer money.",
    ]
    hi = [
        "{bank}: आपके खाते {last4} में ₹{amt} जमा। ओटीपी किसी को न दें।",
        "आपका {app} भुगतान सफल रहा। रेफरेंस [REF]।",
        "ऑर्डर भेज दिया गया है। आधिकारिक ऐप में ट्रैक करें।",
        "माँ, मैं होस्टल पहुँच गया। शाम को फोन करूँगा।",
        "कक्षा 11 बजे है। नोट्स ला देना।",
        "{bank} लॉगिन ओटीपी [OTP] है। इसे साझा न करें।",
        "बिजली बिल आधिकारिक ऐप से चुकाया गया। कोई लिंक नहीं है।",
        "कल परिवार के साथ खाना है। पैसे भेजने की जरूरत नहीं।",
        "कॉलेज की छुट्टी सोमवार को है।",
        "आपकी बस पास नवीनीकृत हो गई।",
        "{bank} ईएमआई कट गई। कोई कार्रवाई नहीं।",
        "डॉक्टर का अपॉइंटमेंट सुबह 10 बजे है।",
        "पुस्तकें पुस्तकालय में जमा कर दो।",
        "वेतन खाते में आ गया है।",
        "ट्रेन समय पर है। प्लेटफॉर्म 3 पर मिलना।",
        "दवाई लेना मत भूलना, लिंक नहीं भेज रहा।",
    ]
    mr = [
        "{bank}: खाते {last4} मध्ये ₹{amt} जमा. OTP कोणाला देऊ नका.",
        "{app} पेमेंट यशस्वी. संदर्भ [REF].",
        "ऑर्डर पाठवला आहे. अधिकृत अॅपमध्ये ट्रॅक करा.",
        "आई, मी कॉलेजमध्ये पोहोचलो. संध्याकाळी फोन करतो.",
        "उद्याची परीक्षा सकाळी १० वाजता आहे.",
        "बिल अधिकृत अॅपने भरले. काही करायची गरज नाही.",
        "{bank} OTP [OTP] आहे. कोणाला सांगू नका.",
        "आई, घरची भाजी आली. पैसे पाठवू नकोस.",
        "कॉलेज सुट्टी आहे. सोमवारी ये.",
        "बस पास नूतनीकरण झाले.",
        "डॉक्टरकडे सकाळी ११ वाजता या.",
        "पगार खात्यात आला आहे.",
        "लाईट बिल भरले. लिंक नाही.",
        "पुस्तके लायब्ररीत जमा कर.",
        "ट्रेन वेळेवर आहे. प्लॅटफॉर्म २.",
        "वाढदिवस मंगल भवन. UPI नको.",
    ]
    hinglish = [
        "{bank} account {last4} me Rs.{amt} credit hua. OTP kisi ko mat dena.",
        "{app} payment successful hai, UPI ref [REF].",
        "Order ship ho gaya, official app me track karna.",
        "Kal college 9 baje milte hain.",
        "Train ticket confirm hai, IRCTC app me dekho.",
        "Light bill official app se paid hai, koi link nahi hai.",
        "OTP [OTP] hai login ke liye, share mat karna.",
        "Parcel delivered successfully, thanks.",
        "Mummy, hostel pahunch gaya, shaam ko call karta hoon.",
        "{bank} EMI kat gayi, koi action nahi chahiye.",
        "Class cancel hai, Monday ko extra lecture.",
        "Salary aa gayi account me, payslip HR portal pe hai.",
        "Doctor appointment 11 baje hai, late mat aana.",
        "Bus pass renew ho gaya.",
        "Birthday dinner ghar pe hai, paise mat bhejna.",
        "WiFi reset hostel office ne kiya, link nahi hai.",
        "Amazon se invoice email pe aaya, official app check karo.",
        "FASTag recharge {bank} se ho gaya Rs.{amt}.",
        "Library book Friday tak return karna.",
        "Meeting 4pm lab me hai.",
    ]

    i = 0
    for lang, templates in [
        ("en", en),
        ("hi", hi),
        ("mr", mr),
        ("hinglish", hinglish),
    ]:
        for tmpl in templates:
            bank = BANKS[i % len(BANKS)]
            app = APPS[i % len(APPS)]
            amt = amounts[i % len(amounts)]
            lf = last4[i % len(last4)]
            i += 1
            text = " ".join(tmpl.format(bank=bank, app=app, amt=amt, last4=lf).split())
            out.append(row(text, lang, "safe", "safe", src, "none"))

    dates = ["01-Sep", "12-Aug", "28-Jul", "06-Sep"]
    for bank, amt, lf, day in zip(
        BANKS * 2,
        amounts * 3,
        last4 * 3,
        dates * 3,
    ):
        out.append(
            row(
                f"{bank}: Rs.{amt} debited from a/c {lf} on {day} at POS. If not you, use official {bank} app.",
                "en",
                "safe",
                "safe",
                src,
                "none",
            )
        )
        out.append(
            row(
                f"{bank} a/c {lf} se Rs.{amt} debit {day} ko. Dispute ke liye official app use karo, koi link nahi.",
                "hinglish",
                "safe",
                "safe",
                src,
                "none",
            )
        )

    contrast = [
        ("en", "{bank} KYC is already complete. We will never ask you to click a link or share OTP."),
        ("en", "Your {bank} video KYC appointment is booked in the official app only. Ignore other SMS links."),
        ("en", "{bank}: UPI is active. Do not share UPI PIN with anyone, including people claiming to be staff."),
        ("en", "Job application received by the college placement cell. We never ask for a registration fee."),
        ("en", "Your loan EMI is paid. {bank} will not call to ask for a processing fee refund."),
        ("en", "Package delivered. If a courier asks for extra customs pay by unknown link, refuse and use the shop app."),
        ("hi", "{bank} केवाईसी पूरा है। लिंक पर क्लिक न करें और ओटीपी साझा न करें।"),
        ("hi", "{bank} आधिकारिक ऐप से ही बैंकिंग करें। कॉल पर पिन न बताएँ।"),
        ("hi", "नौकरी के लिए कॉलेज पोर्टल पर आवेदन हुआ। कोई फीस नहीं।"),
        ("mr", "{bank} KYC पूर्ण आहे. लिंक उघडू नका. OTP देऊ नका."),
        ("mr", "अधिकृत बँक अॅप वापरा. कॉलवर पिन सांगू नका."),
        ("mr", "प्लेसमेंट अर्ज प्राप्त. फी मागत नाही."),
        ("hinglish", "{bank} KYC already complete hai. Koi link mat kholna, OTP mat dena."),
        ("hinglish", "Official {bank} app se hi login karo. Customer care OTP nahi mangta."),
        ("hinglish", "UPI PIN kabhi share mat karna, refund ke naam pe bhi nahi."),
        ("hinglish", "Job ke liye college portal use hua, koi registration fee nahi."),
        ("hinglish", "Loan EMI paid hai, processing fee ke naam pe paise mat bhejna."),
        ("hinglish", "Parcel deliver ho gaya. Extra customs link pe mat bhugtan karna."),
    ]
    for lang, tmpl in contrast:
        for bank in BANKS[:4]:
            out.append(
                row(tmpl.format(bank=bank), lang, "safe", "safe", src, "none")
            )

    extra = [
        row(
            "Your train ticket has been booked successfully.",
            "en",
            "safe",
            "safe",
            src,
            "none",
        ),
        row(
            "Your parcel has been delivered successfully.",
            "en",
            "safe",
            "safe",
            src,
            "none",
        ),
        row("Thank you for your purchase.", "en", "safe", "safe", src, "none"),
        row(
            "Your payment of ₹899 has been received.",
            "en",
            "safe",
            "safe",
            src,
            "none",
        ),
    ]
    out.extend(extra)
    return out


def infer_hf_type(text: str, label: str) -> str:
    if label != "scam":
        return "safe"
    t = text.lower()
    if "kyc" in t or "केवाईसी" in t:
        return "kyc"
    if "loan" in t or "लोन" in t:
        return "loan"
    if "parcel" in t or "customs" in t or "पार्सल" in t:
        return "delivery"
    if "atm" in t or "खाता" in t or "bank" in t:
        return "bank_impersonation"
    return "other"


def infer_indicators(text: str, scam_type: str) -> str:
    if scam_type == "safe":
        return "none"
    bits = []
    low = text.lower()
    if any(w in low for w in ["urgent", "immediately", "jaldi", "तुरंत", "turant"]):
        bits.append("urgency")
    if "kyc" in low or "केवाईसी" in low:
        bits.append("kyc_language")
    if "http" in low or "click" in low:
        bits.append("suspicious_url")
    if "otp" in low or "pin" in low:
        bits.append("otp_request")
    if scam_type not in bits:
        bits.append(scam_type)
    return "|".join(bits)


NOISY_LEGIT = ("jaldi kare", "please act now", "immediately", "abhi kare")


def load_hf_rows() -> list[dict]:
    if not RAW_HF.exists():
        return []
    out = []
    with RAW_HF.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for rec in reader:
            text = (rec.get("message") or "").strip()
            label_raw = (rec.get("label") or "").strip().lower()
            lang_raw = (rec.get("language") or "English").strip().lower()
            if not text:
                continue
            label = "scam" if label_raw == "scam" else "safe"
            if label == "safe" and any(n in text.lower() for n in NOISY_LEGIT):
                # Public file mixes urgency phrases into "legit" rows; skip those.
                continue
            lang = {"hindi": "hi", "english": "en", "hinglish": "hinglish"}.get(
                lang_raw, "en"
            )
            scam_type = infer_hf_type(text, label)
            out.append(
                row(
                    text,
                    lang,
                    label,
                    scam_type,
                    "hf_karanverma19",
                    infer_indicators(text, scam_type),
                )
            )
    return out


def dedupe(rows: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for r in rows:
        key = (r["text"].casefold(), r["language"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(r)
    return unique


def stratified_split(rows: list[dict]) -> list[dict]:
    rng = random.Random(SEED)
    buckets: dict[tuple, list] = defaultdict(list)
    for r in rows:
        buckets[(r["scam_or_safe"], r["scam_type"], r["language"])].append(r)

    assigned = []
    for items in buckets.values():
        rng.shuffle(items)
        n = len(items)
        if n == 1:
            cuts = [("train", items)]
        elif n == 2:
            cuts = [("train", items[:1]), ("test", items[1:])]
        elif n == 3:
            cuts = [
                ("train", items[:1]),
                ("validation", items[1:2]),
                ("test", items[2:]),
            ]
        else:
            n_train = int(n * 0.70)
            n_val = int(n * 0.15)
            n_train = max(n_train, 1)
            n_val = max(n_val, 1)
            n_test = n - n_train - n_val
            if n_test < 1:
                n_test = 1
                n_train = n - n_val - n_test
            cuts = [
                ("train", items[:n_train]),
                ("validation", items[n_train : n_train + n_val]),
                ("test", items[n_train + n_val :]),
            ]
        for split_name, chunk in cuts:
            for r in chunk:
                r = dict(r)
                r["split"] = split_name
                assigned.append(r)
    rng.shuffle(assigned)
    return assigned


def add_ids(rows: list[dict]) -> list[dict]:
    out = []
    for i, r in enumerate(rows, start=1):
        item = {"id": f"ss-{i:06d}"}
        item.update(r)
        out.append(item)
    return out


FIELDS = [
    "id",
    "text",
    "language",
    "scam_or_safe",
    "scam_type",
    "source",
    "indicators",
    "split",
]


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)


def counts(rows: list[dict], key: str) -> dict:
    c: dict[str, int] = defaultdict(int)
    for r in rows:
        c[r[key]] += 1
    return dict(sorted(c.items(), key=lambda x: (-x[1], x[0])))


def main() -> None:
    rows = dedupe(synthetic_scams() + synthetic_safe() + load_hf_rows())
    rows = stratified_split(rows)
    rows = add_ids(rows)

    processed = DATA / "processed" / "messages.csv"
    write_csv(processed, rows)
    write_csv(DATA / "train" / "messages.csv", [r for r in rows if r["split"] == "train"])
    write_csv(
        DATA / "validation" / "messages.csv",
        [r for r in rows if r["split"] == "validation"],
    )
    write_csv(DATA / "test" / "messages.csv", [r for r in rows if r["split"] == "test"])

    summary = {
        "seed": SEED,
        "n_total": len(rows),
        "n_train": sum(r["split"] == "train" for r in rows),
        "n_validation": sum(r["split"] == "validation" for r in rows),
        "n_test": sum(r["split"] == "test" for r in rows),
        "by_label": counts(rows, "scam_or_safe"),
        "by_type": counts(rows, "scam_type"),
        "by_language": counts(rows, "language"),
        "by_source": counts(rows, "source"),
        "test_is_frozen": True,
        "note": "Do not use test/ for training or model selection.",
    }
    summary_path = DATA / "processed" / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
