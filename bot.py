from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
from collections import OrderedDict
from dataclasses import dataclass
from io import BytesIO
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import urlparse



os.environ.setdefault("OPENCV_LOG_LEVEL", "SILENT")

import nextcord
from dotenv import load_dotenv
from nextcord.ext import commands



try:
    from PIL import ImageFile as _PILImageFile

    _PILImageFile.LOAD_TRUNCATED_IMAGES = True
except Exception:
    pass



load_dotenv()

log = logging.getLogger("safety")


def _env_int(name: str, default: int) -> int:
    try:
        return int(str(os.environ.get(name, "")).strip() or default)
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(str(os.environ.get(name, "")).strip() or default)
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = str(os.environ.get(name, "")).strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on", "y"}


def _env_ids(name: str, default: set) -> set:
    raw = os.environ.get(name, "")
    parsed = {int(part) for part in re.split(r"[,\s]+", raw) if part.strip().lstrip("-").isdigit()}
    return parsed or set(default)


def _env_words(name: str, default: set) -> set:
    raw = os.environ.get(name, "")
    parsed = {part.strip().lower() for part in re.split(r"[,\s]+", raw) if part.strip()}
    return parsed or set(default)



ALERT_USER_ID = _env_int("ALERT_USER_ID", 920819377627099166)
ALERT_MESSAGE = f"<@{ALERT_USER_ID}>"


ALLOWED_CHANNEL_IDS = _env_ids("ALLOWED_CHANNEL_IDS", set())
MODERATION_BYPASS_ROLE_IDS = _env_ids(
    "MODERATION_BYPASS_ROLE_IDS",
    {
        1514376334372241449,
        1407922165369802854,
        1407922499882061974,
        1407120344304586802,
        1000843059824697434,
    },
)


def is_watched_channel(channel_id) -> bool:
    return (not ALLOWED_CHANNEL_IDS) or (channel_id in ALLOWED_CHANNEL_IDS)


def has_moderation_bypass_role(member) -> bool:
    role_ids = {getattr(role, "id", None) for role in getattr(member, "roles", [])}
    return bool(role_ids & MODERATION_BYPASS_ROLE_IDS)

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}
VIDEO_EXTENSIONS = {".mp4", ".mov", ".webm", ".m4v", ".mkv"}
AUDIO_EXTENSIONS = {".ogg", ".oga", ".opus", ".m4a", ".mp3", ".wav", ".flac", ".aac", ".aiff", ".aif"}


MAX_SCAN_BYTES = _env_int("MAX_SCAN_BYTES", 8 * 1024 * 1024)
MAX_VIDEO_SCAN_BYTES = _env_int("MAX_VIDEO_SCAN_BYTES", 32 * 1024 * 1024)
MAX_AUDIO_SCAN_BYTES = _env_int("MAX_AUDIO_SCAN_BYTES", 16 * 1024 * 1024)
MAX_AUDIO_SECONDS = _env_int("MAX_AUDIO_SECONDS", 60)
MAX_OCR_FRAMES = _env_int("MAX_OCR_FRAMES", 12)
MAX_NSFW_FRAMES = _env_int("MAX_NSFW_FRAMES", 4)
MAX_VIDEO_FRAMES = _env_int("MAX_VIDEO_FRAMES", 5)
OCR_CONFIDENCE_THRESHOLD = _env_float("OCR_CONFIDENCE_THRESHOLD", 0.45)
OCR_UPSCALE_TARGET = _env_int("OCR_UPSCALE_TARGET", 1000)
NSFW_SCORE_THRESHOLD = _env_float("NSFW_SCORE_THRESHOLD", 0.55)
ALERT_THRESHOLD = _env_int("ALERT_THRESHOLD", 70)





SCAN_CONCURRENCY = max(1, _env_int("SCAN_CONCURRENCY", 2))
SCAN_TIMEOUT_SECONDS = _env_int("SCAN_TIMEOUT_SECONDS", 60)
MAX_ALERTED_IDS = _env_int("MAX_ALERTED_IDS", 5000)
DOWNLOAD_CHUNK_BYTES = 64 * 1024
HTTP_TIMEOUT_SECONDS = _env_int("HTTP_TIMEOUT_SECONDS", 20)




MAX_INVITES_PER_MESSAGE = max(1, _env_int("MAX_INVITES_PER_MESSAGE", 3))
INVITE_RESOLVE_TIMEOUT = _env_int("INVITE_RESOLVE_TIMEOUT", 10)
INVITE_CACHE_TTL = _env_int("INVITE_CACHE_TTL", 600)
INVITE_CACHE_MAX = _env_int("INVITE_CACHE_MAX", 2000)



FLAG_ALL_INVITES = _env_bool("FLAG_ALL_INVITES", True)
INVITE_BASE_SCORE = _env_int("INVITE_BASE_SCORE", ALERT_THRESHOLD)
ALLOWED_INVITE_CODES = _env_words("ALLOWED_INVITE_CODES", {"gohar"})




RESTART_MIN_BACKOFF = _env_float("RESTART_MIN_BACKOFF", 3.0)
RESTART_MAX_BACKOFF = _env_float("RESTART_MAX_BACKOFF", 300.0)
HEARTBEAT_LOG_INTERVAL = _env_int("HEARTBEAT_LOG_INTERVAL", 300)
LOG_FILE = os.environ.get("LOG_FILE", "safety_bot.log")
AUDIO_LANGUAGE = os.environ.get("AUDIO_LANGUAGE", "en-US")

URL_RE = re.compile(r"https?://|discord\.gift|discord\.gg|www\.", re.IGNORECASE)
SHORTENER_RE = re.compile(
    r"\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|rebrand\.ly|rb\.gy)\b",
    re.IGNORECASE,
)
SUSPICIOUS_DOMAIN_RE = re.compile(
    r"\b[\w.-]+\.(?:ru|cn|top|xyz|click|link|zip|mov|work|live|site|online|shop|gift|claim|win)\b",
    re.IGNORECASE,
)
MONEY_RE = re.compile(
    r"(?:\$\s?\d"
    r"|\d[\d,]*\s*(?:k\b|grand|dollars?|usd|usdt|euros?|pounds?|bucks|thousand|million|billion)"
    r"|(?:hundred|thousand|million|billion)\s+(?:dollars?|usd|euros?|pounds?|bucks)"
    r"|\bdollars?\b|\beuros?\b"
    r"|usd|cash(?:\s*app)?|money|gift\s*card|nitro|robux|v-?bucks|crypto|bitcoin|btc|eth|paypal|venmo|zelle)",
    re.IGNORECASE,
)
HANDLE_RE = re.compile(r"@(?:everyone|here|[\w.-]{2,32})|<@!?\d{17,20}>", re.IGNORECASE)
DM_LURE_RE = re.compile(
    r"\b(?:dm|dms|pm|pms|msg|message|inbox|hmu|contact|text|add)\s+me\b"
    r"|\bdm\s+(?:me|us)\b"
    r"|\b(?:dm|dms|pm|pms|msg|message|contact|text|add)\s+(?:@[\w.-]{2,32}\b|<@!?\d{17,20}>)"
    r"|\bfirst\s+(?:\d+|person|people|few|one|to)\b"
    r"|\bwho(?:ever)?\s+(?:dms|messages|pms|contacts)\b",
    re.IGNORECASE,
)
META_EXAMPLE_RE = re.compile(
    r"\b(?:for example|example|hypothetically|imagine|something like|it's like|its like)\b"
    r"|\b(?:if|when|whenever)\s+someone\s+(?:says?|posts?|sends?|messages?)\b"
    r"|\b(?:someone|people)\s+(?:saying|posting|sending|messaging)\b",
    re.IGNORECASE,
)
CONVERSATION_RE = re.compile(
    r"\b(?:is this|does this|would this|could this|should this|why does this)\b"
    r"|\b(?:i got scammed|got scammed|this is a scam|looks like a scam|watch out|be careful|avoid this)\b"
    r"|\b(?:someone told me|someone sent me|they told me|they sent me|my friend sent me)\b"
    r"|\b(?:talking about|asking about|discussing|explaining)\b",
    re.IGNORECASE,
)
LESSON_RE = re.compile(
    r"\b(?:scam alert|scam warning|scam example|phishing example|phishing awareness|security lesson)\b"
    r"|\b(?:lesson|educational|training|awareness|red flags?|avoid scams?|spot scams?)\b"
    r"|\b(?:lorem ipsum|placeholder|dummy text|sample text|example graphic)\b"
    r"|\b(?:obviously fake|sarcasm|sarcastic|not a real offer)\b|/s\b",
    re.IGNORECASE,
)
HOOK_RE = re.compile(
    r"\b(?:get|getting|become|becoming)\s+rich\b"
    r"|\brich\s+quick\b"
    r"|\bmake\s+money\s+fast\b"
    r"|\bquick\s+(?:way|may)\s+to\s+make\s+money\b"
    r"|\bquick\s+(?:money|cash)\b"
    r"|\bchance\s+to\s+make\b"
    r"|\bchance\s+to\s+win\b"
    r"|\bwin\s+(?:\$|\d|big|one\s+(?:hundred|thousand|million|billion))",
    re.IGNORECASE,
)
OFF_PLATFORM_RE = re.compile(
    r"\b(?:telegram|whatsapp|whats\s*app|signal|wechat|kik|snapchat|t\.me)\b",
    re.IGNORECASE,
)
BONUS_CODE_RE = re.compile(
    r"\b(?:activate|enter|use|apply|redeem)\s+(?:the\s+)?(?:promo\s+)?code\b"
    r"|\b(?:promo|bonus|invite)\s+code\b"
    r"|\bcode\s+for\s+bonu",
    re.IGNORECASE,
)
CRYPTO_ASSET_RE = re.compile(
    r"\b(?:usdt|btc|bitcoin|eth|ethereum|trx|trc20|trc|crypto|token|wallet|block\s*explorer)\b",
    re.IGNORECASE,
)
CRYPTO_RECEIPT_RE = re.compile(
    r"\b(?:withdrawal success|transaction history|received|completed|network fee|sender|check explorer|view on block explorer)\b"
    r"|\b(?:withdrawal|withdraw|deposit)\s+(?:success|amount|completed)\b"
    r"|\+\s?\d[\d,.]*\s*(?:usdt|btc|eth|trx)\b",
    re.IGNORECASE,
)
DEBT_DEMAND_RE = re.compile(
    r"\b(?:balance due|full balance|recover balance|recover the full balance|unpaid|overdue|arrears|debt|fine|owed)\b"
    r"|\b(?:client has instructed|reference|ref:|case number|account number)\b",
    re.IGNORECASE,
)
THREAT_RE = re.compile(
    r"\b(?:do not ignore|important message|final notice|urgent|immediate action)\b"
    r"|\b(?:enforcement agents?|bailiffs?|legal action|court action|warrant|arrest|seizure)\b"
    r"|\b(?:take control of goods|control of goods|attending|attend your address|recover in full)\b"
    r"|\bwithin\s+\d+\s+(?:hours?|days?|weeks?)\b",
    re.IGNORECASE,
)
BARE_DOMAIN_RE = re.compile(
    r"\b[\w-]{2,}\.(?:com|net|org|io|me|gg|co|app|info|biz|live|online|site|shop|store|vip|win|top|fun|cc|tk|ml|xyz|click|link)\b",
    re.IGNORECASE,
)
ACCOUNT_PHISH_RE = re.compile(
    r"\b(?:account|profile|login|wallet)\s+(?:has been\s+|is\s+|was\s+)?(?:suspended|locked|disabled|restricted|flagged|compromised|terminated|deactivated)\b"
    r"|\b(?:suspicious|unusual|unauthorized|unrecognized)\s+(?:login|activity|sign[- ]?in|access|attempt)\b"
    r"|\b(?:verify|confirm|secure|reactivate|restore|update)\s+(?:your\s+)?(?:account|identity|password|login|details|information|wallet)\b"
    r"|\byour\s+account\s+will\s+be\b"
    r"|\b(?:confirm|verify)\s+your\s+identity\b",
    re.IGNORECASE,
)
INVESTMENT_RE = re.compile(
    r"\b(?:double|triple|2x|3x|5x|10x|x2|x3|x5|x10)\s+your\s+(?:money|crypto|btc|eth|usdt|investment|deposit|coins?|funds?)\b"
    r"|\b(?:guaranteed|risk[- ]?free)\s+(?:profit|returns?|roi|income|payout|earnings?)\b"
    r"|\b(?:passive income|profit daily|daily profit|trading signals?|investment opportunity|earn from home|flip your money)\b"
    r"|\bsend\s+\d[\d,.]*\s*(?:\$|usd|usdt|btc|eth)?.{0,20}\b(?:get|receive|back)\s+\d"
    r"|\b(?:invest|deposit)\s+\$?\d[\d,]*\s+(?:and|to)\s+(?:get|earn|receive|make)\b",
    re.IGNORECASE,
)
GAMBLING_RE = re.compile(
    r"\b(?:casino|jackpot|free spins?|betting|sportsbook|roulette|slots?|wager|stake\.com|1xbet|deposit bonus|sign[- ]?up bonus|no deposit bonus|rakeback)\b",
    re.IGNORECASE,
)
FREE_NITRO_RE = re.compile(
    r"\b(?:free\s+(?:discord\s+)?nitro|nitro\s+(?:for\s+)?free|gift(?:ed)?\s+nitro|free\s+(?:steam\s+)?(?:gift|game|key|skins?|robux|v-?bucks))\b"
    r"|\b(?:claim|get|grab|collect)\s+(?:your\s+)?free\s+nitro\b"
    r"|\bsteamcommunity\b",
    re.IGNORECASE,
)
ADVANCE_FEE_RE = re.compile(
    r"(?:private\s*bank\s*code|transfer\s*code|security\s*prot|code\s*purchase|purchasable\s*code|purchase\s*the\s*code)"
    r"|(?:withdrawal|transfer|security|activation|processing)\s*(?:fee|code)"
    r"|(?:fee|cost|amount)\s*(?:to|for|of)?\s*(?:complete|process|release|unlock|access|purchase|withdrawal)"
    r"|provide\s*amount\s*to\s*the\s*bank"
    r"|cannot\s*be\s*(?:paid|deducted)"
    r"|deducted\s*from\s*your\s*[\w\s]*balance"
    r"|withdrawal\s*(?:process|access)"
    r"|complete\s*your\s*withdrawal"
    r"|once\s*we\s*receive\s*(?:the\s*)?\$?\d"
    r"|send\s*to\s*your\s*(?:mail|sms)"
    r"|xchangepay",
    re.IGNORECASE,
)
INVITE_RE = re.compile(
    r"(?:https?://)?(?:www\.)?(?:discord\.gg|discord(?:app)?\.com/invite)/+([a-z0-9][a-z0-9-]{1,31})",
    re.IGNORECASE,
)
NSFW_TERMS_RE = re.compile(
    r"\b(?:18\s*\+|nsfw|porn|porno|hentai|nude|nudes|naked|onlyfans|o\.?f\.?\s+leaks?|lewd|lewds|"
    r"sex|sexting|sexual|xxx|r18|r-?18|fetish|kink|camgirl|cam\s*girl|escort|hookup|hook\s*up|"
    r"e-?girl|slut|thot|boobs|tits|pussy|cock|cum|gooning?|goon\s*cave)\b",
    re.IGNORECASE,
)


YOUTH_TERMS_RE = re.compile(
    r"\b(?:little|young|younger|youth|teen|teens|teenage|minor|minors|loli|lolis|shota|jb|"
    r"jailbait|kid|kids|child|children|preteen|pre-?teen|underage)\b",
    re.IGNORECASE,
)

GUILD_NSFW_LEVELS_FLAGGED = {1, 3}

REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "image/avif,image/webp,image/gif,video/*,*/*;q=0.8",
}


def collapse_spaced_letters(text: str) -> str:
    return re.sub(
        r"\b(?:[a-z0-9] ){3,}[a-z0-9]\b",
        lambda match: match.group(0).replace(" ", ""),
        text,
    )

BRAND_TERMS = (
    "mrbeast",
    "mr beast",
    "discord",
    "nitro",
    "steam",
    "roblox",
    "fortnite",
    "cash app",
    "paypal",
    "apple",
    "amazon",
    "google",
    "youtube",
)
GIVEAWAY_TERMS = (
    "giveaway",
    "winner",
    "won",
    "prize",
    "reward",
    "free",
    "limited time",
    "congratulations",
    "selected",
    "airdrop",
    "bonus",
    "bonuses",
    "giving away",
    "give away",
    "handing out",
    "free money",
    "free cash",
    "rakeback",
)
STRONG_ACTION_TERMS = (
    "claim",
    "verify",
    "register",
    "login",
    "log in",
    "sign in",
    "sign up",
    "redeem",
    "activate code",
    "promo code",
    "scan qr",
    "scan the qr",
    "connect wallet",
    "seed phrase",
    "password",
    "enter code",
    "payment",
    "withdrawal",
)
WEAK_ACTION_TERMS = (
    "click",
    "tap",
    "go to",
    "open",
    "visit",
    "page",
    "continue",
    "follow",
    "subscribe",
)
PARODY_TERMS = (
    "joke",
    "meme",
    "parody",
    "satire",
    "fake",
    "shitpost",
    "sketch",
    "drawing",
    "drawn",
)
GAME_RESULT_TERMS = (
    "game review",
    "rematch",
    "new 1 min",
    "well done",
    "built a lead",
    "brilliant",
    "great",
    "best",
    "timeout",
)
AD_CONTEXT_TERMS = (
    "ad",
    "learn more",
    "remove ads",
    "sponsored",
    "advertisement",
)
NSFW_CLASSES = {
    "ANUS_EXPOSED",
    "BUTTOCKS_EXPOSED",
    "FEMALE_BREAST_EXPOSED",
    "FEMALE_GENITALIA_EXPOSED",
    "MALE_GENITALIA_EXPOSED",
    "EXPOSED_ANUS",
    "EXPOSED_BUTTOCKS",
    "EXPOSED_BREAST",
    "EXPOSED_BREASTS",
    "EXPOSED_VAGINA",
    "EXPOSED_PENIS",
}

_rapid_ocr = None
_rapid_ocr_unavailable = False
_nude_detector = None
_nude_detector_unavailable = False


@dataclass(frozen=True)
class ScamAssessment:
    score: int
    reasons: tuple[str, ...]
    scanned_text: str = ""
    content_kind: str = "image"

    @property
    def should_alert(self) -> bool:
        return self.score >= ALERT_THRESHOLD


def normalize_text(value: Optional[str]) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip().lower()


def strip_discord_markup(text: str) -> str:

    return re.sub(r"[|*_~`]", "", text or "")


def invite_match_text(text: str) -> str:
    text = strip_discord_markup(text or "")
    text = re.sub(r"[\u200b\u200c\u200d\ufeff]", "", text)
    text = re.sub(r"\bdot\b", ".", text, flags=re.IGNORECASE)
    text = re.sub(r"\bslash\b", "/", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*([./])\s*", r"\1", text)
    return re.sub(r"\s+", " ", text)


def contains_any(text: str, terms: Iterable[str]) -> bool:
    return any(term in text for term in terms)


def clip(text: str, limit: int = 1000) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 20] + "\n... *(truncated)*"


def assess_scam_text(
    text: str,
    *,
    has_qr: bool = False,
    has_media: bool = True,
    nsfw_detections: Iterable[str] = (),
    content_kind: str = "image",
) -> ScamAssessment:
    normalized = collapse_spaced_letters(strip_discord_markup(normalize_text(text)))
    score = 0
    reasons: list[str] = []
    nsfw_detections = tuple(nsfw_detections)

    if has_media:
        score += 5

    if nsfw_detections:
        score += 100
        reasons.append("explicit/adult visual content")

    has_brand = contains_any(normalized, BRAND_TERMS)
    has_money = bool(MONEY_RE.search(normalized))
    has_hook = bool(HOOK_RE.search(normalized))
    has_giveaway = contains_any(normalized, GIVEAWAY_TERMS) or has_money or has_hook
    has_strong_action = contains_any(normalized, STRONG_ACTION_TERMS)
    has_weak_action = contains_any(normalized, WEAK_ACTION_TERMS)
    has_dm_lure = bool(DM_LURE_RE.search(normalized))
    has_off_platform = bool(OFF_PLATFORM_RE.search(normalized))
    has_bonus_code = bool(BONUS_CODE_RE.search(normalized))
    has_crypto_asset = bool(CRYPTO_ASSET_RE.search(normalized))
    has_crypto_receipt = bool(CRYPTO_RECEIPT_RE.search(normalized))
    has_debt_demand = bool(DEBT_DEMAND_RE.search(normalized))
    has_threat = bool(THREAT_RE.search(normalized))
    has_account_phish = bool(ACCOUNT_PHISH_RE.search(normalized))
    has_investment = bool(INVESTMENT_RE.search(normalized))
    has_gambling = bool(GAMBLING_RE.search(normalized))
    has_free_nitro = bool(FREE_NITRO_RE.search(normalized))
    has_advance_fee = bool(ADVANCE_FEE_RE.search(normalized))
    has_bare_domain = bool(BARE_DOMAIN_RE.search(normalized))
    has_url = bool(URL_RE.search(normalized) or SHORTENER_RE.search(normalized) or SUSPICIOUS_DOMAIN_RE.search(normalized))
    has_parody = contains_any(normalized, PARODY_TERMS)
    is_meta_example = bool(META_EXAMPLE_RE.search(normalized))
    is_conversation = bool(CONVERSATION_RE.search(normalized))
    is_lesson = bool(LESSON_RE.search(normalized))
    game_result_terms = sum(term in normalized for term in GAME_RESULT_TERMS)
    ad_context_terms = sum(term in normalized for term in AD_CONTEXT_TERMS)
    has_link_instruction = bool(re.search(r"\b(?:go to|visit|open|click|tap)\b", normalized))
    has_direct_instruction = bool(
        re.search(
            r"\b(?:claim|verify|register|log\s*in|login|sign\s*in|sign\s*up|redeem|scan|connect wallet|enter code)\b",
            normalized,
        )
    )
    has_risky_instruction = has_direct_instruction or has_dm_lure or has_qr or has_off_platform or has_link_instruction
    has_delivery_path = has_url or has_bare_domain or has_qr or has_dm_lure or has_strong_action or has_off_platform
    has_domain_reward = (has_url or has_bare_domain) and has_giveaway
    has_private_reward = has_dm_lure and has_giveaway

    if has_brand:
        score += 15
        reasons.append("brand or creator name")

    if has_giveaway:
        score += 20
        reasons.append("money, giveaway, prize, or reward wording")

    if has_strong_action:
        score += 25
        reasons.append("asks users to claim, verify, log in, scan, or enter info")
    elif has_weak_action:
        score += 5
        reasons.append("call-to-action wording")

    if has_dm_lure:
        score += 25
        reasons.append("asks people to DM or contact privately")

    if has_money and has_dm_lure:
        score += 30
        reasons.append("money/prize offer plus private contact")
    elif has_giveaway and has_dm_lure:
        score += 10
        reasons.append("giveaway wording plus private contact")

    if has_bare_domain and not has_url:
        score += 20
        reasons.append("external website")

    if has_domain_reward:
        score += 35
        reasons.append("external website tied to a reward offer")

    if has_off_platform and (has_dm_lure or has_url or has_bare_domain):
        score += 20
        reasons.append("moves users to another app")

    if has_bonus_code:
        score += 45
        reasons.append("bonus or promo code lure")

    if has_bonus_code and has_giveaway:
        score += 20
        reasons.append("bonus code plus reward wording")

    if has_crypto_asset and has_crypto_receipt and has_money:
        score += 45
        reasons.append("crypto withdrawal or payment proof")

    elif has_crypto_asset and has_crypto_receipt:
        score += 25
        reasons.append("crypto transaction wording")

    if has_debt_demand:
        score += 25
        reasons.append("debt, balance, fine, or account demand")

    if has_threat:
        score += 30
        reasons.append("urgent legal, enforcement, or intimidation wording")

    if has_debt_demand and has_threat:
        score += 30
        reasons.append("debt demand plus threat or urgency")

    if has_account_phish:
        score += 30
        reasons.append("account suspension or verification phishing")

    if has_account_phish and (has_url or has_bare_domain or has_qr):
        score += 15
        reasons.append("account phishing tied to a link or QR code")

    if has_investment:
        score += 25
        reasons.append("get-rich, double-your-money, or guaranteed-returns pitch")

    if has_investment and (has_off_platform or has_dm_lure or has_url or has_bare_domain or has_crypto_asset):
        score += 15
        reasons.append("investment pitch with a contact or payment path")

    if has_gambling and (has_bonus_code or has_url or has_bare_domain or has_giveaway):
        score += 20
        reasons.append("gambling or casino bonus lure")

    if has_free_nitro:
        score += 25
        reasons.append("free Nitro, gift, or skins lure")

    if has_free_nitro and (has_url or has_bare_domain or has_qr or has_dm_lure):
        score += 20
        reasons.append("free Nitro/gift lure with a link or contact path")

    if has_advance_fee:
        score += 45
        reasons.append("advance-fee withdrawal or code-purchase wording")

    if has_advance_fee and has_money:
        score += 20
        reasons.append("advance-fee wording tied to a payment amount")

    if has_advance_fee and ("withdrawal" in normalized or "account" in normalized or has_crypto_receipt):
        score += 15
        reasons.append("payment/code request tied to withdrawal or account access")

    if has_url:
        score += 30
        reasons.append("link or suspicious domain")

    if has_url and has_giveaway:
        score += 25
        reasons.append("link tied to a reward offer")

    if has_qr:
        score += 30
        reasons.append("QR code")

    if HANDLE_RE.search(normalized) and has_giveaway:
        score += 10
        reasons.append("mention plus reward wording")

    if has_brand and has_giveaway and (has_strong_action or has_url or has_qr):
        score += 15
        reasons.append("brand, reward, and risky action")

    if has_brand and has_giveaway and has_weak_action and not has_strong_action and not has_url and not has_qr:
        score += 25
        reasons.append("creator giveaway ad wording")

    if has_parody and not has_url and not has_qr and not has_strong_action:
        score = max(0, score - 25)
        reasons.append("joke/parody wording without a risky action")

    if is_meta_example and not has_url and not has_qr and not has_bare_domain and not has_strong_action:
        score = max(0, score - 60)
        reasons.append("talking about an example instead of making the offer")

    if is_lesson and not has_risky_instruction:
        score = min(score, 45)
        reasons.append("looks like a lesson, warning, or sarcastic example")

    if game_result_terms >= 2 and not has_strong_action and not has_dm_lure and not has_qr and not has_brand:
        score = max(0, score - 85)
        reasons.append("looks like a game result screen")

    if is_conversation and not has_domain_reward and not has_private_reward and not has_qr and not has_strong_action:
        score = min(score, 45)
        reasons.append("looks like discussion instead of a live scam")

    if ad_context_terms >= 2 and not has_domain_reward and not has_dm_lure and not has_qr and not has_strong_action:
        score = min(score, 45)
        reasons.append("looks like a normal ad or app screen")

    if has_giveaway and not has_delivery_path and not has_brand:
        score = min(score, 55)
        reasons.append("reward wording without a link, domain, QR, login, or DM path")

    score = min(score, 100)

    return ScamAssessment(
        score=score,
        reasons=tuple(reasons),
        scanned_text=clip(text, 500),
        content_kind=content_kind,
    )


def extract_invite_codes(text: str) -> list[str]:
    codes: list[str] = []

    for match in INVITE_RE.finditer(invite_match_text(text)):
        code = match.group(1)
        if code.lower() == "invite" or code in codes:
            continue
        codes.append(code)
    return codes


def normalize_invite_code(code: str) -> str:
    return str(code or "").strip().lower()


def is_allowed_invite_code(code: str) -> bool:
    return normalize_invite_code(code) in ALLOWED_INVITE_CODES


def disallowed_invite_codes(text: str) -> list[str]:
    return [code for code in extract_invite_codes(text) if not is_allowed_invite_code(code)]


def assess_invite_guild(
    name: str,
    description: str = "",
    nsfw_level=None,
    nsfw_flag: bool = False,
) -> ScamAssessment:

    name = name or ""
    description = description or ""
    invite_text = "\n".join(part for part in (name, description) if part).strip()

    base = assess_scam_text(invite_text, has_media=False, content_kind="invite")
    score = base.score
    reasons = list(base.reasons)
    normalized = normalize_text(invite_text)

    try:
        level = int(nsfw_level) if nsfw_level is not None else None
    except (TypeError, ValueError):
        level = None

    age_restricted = bool(nsfw_flag) or level in GUILD_NSFW_LEVELS_FLAGGED
    has_nsfw_terms = bool(NSFW_TERMS_RE.search(normalized))

    if age_restricted:
        score = max(score, 90)
        reasons.append("Discord flags this invite's server as adult / age-restricted (18+)")

    if has_nsfw_terms:
        score = max(score, 85)
        reasons.append("server name or description contains explicit/NSFW wording")

    if (age_restricted or has_nsfw_terms) and YOUTH_TERMS_RE.search(normalized):
        score = 100
        reasons.append("adult server with youth-referencing wording — possible CSAM, escalate to a human")

    score = min(score, 100)
    label = f"invite -> {name}".strip()
    if description:
        label += f" - {description}"

    return ScamAssessment(
        score=score,
        reasons=tuple(reasons) or ("discord server invite",),
        scanned_text=clip(label, 500),
        content_kind="invite",
    )


def invite_link_assessment(code: str) -> ScamAssessment:
    return ScamAssessment(
        score=max(INVITE_BASE_SCORE, ALERT_THRESHOLD),
        reasons=("contains a Discord server invite link",),
        scanned_text=clip(f"invite -> {code}", 500),
        content_kind="invite",
    )


def first_invite_link_assessment(text: str) -> Optional[ScamAssessment]:
    if not FLAG_ALL_INVITES:
        return None
    codes = disallowed_invite_codes(text)[:MAX_INVITES_PER_MESSAGE]
    if not codes:
        return None
    return invite_link_assessment(codes[0])


def apply_invite_policy(code: str, resolved: Optional[ScamAssessment]) -> Optional[ScamAssessment]:
    if is_allowed_invite_code(code):
        return None

    if resolved is not None and resolved.should_alert:
        return resolved

    if not FLAG_ALL_INVITES:
        return resolved

    if resolved is not None:
        score = max(INVITE_BASE_SCORE, resolved.score)
        label = resolved.scanned_text or f"invite -> {code}"
        reasons = [r for r in resolved.reasons if r != "discord server invite"]
        if not reasons:
            reasons = ["contains a Discord server invite link"]
    else:
        score = INVITE_BASE_SCORE
        label = f"invite -> {code}"
        reasons = ["contains a Discord server invite link"]

    return ScamAssessment(
        score=min(score, 100),
        reasons=tuple(reasons),
        scanned_text=clip(label, 500),
        content_kind="invite",
    )


def is_visual_attachment(attachment) -> bool:
    content_type = normalize_text(getattr(attachment, "content_type", ""))
    filename = normalize_text(getattr(attachment, "filename", ""))
    suffix = Path(filename).suffix
    return content_type.startswith("image/") or suffix in IMAGE_EXTENSIONS


def is_video_attachment(attachment) -> bool:
    content_type = normalize_text(getattr(attachment, "content_type", ""))
    filename = normalize_text(getattr(attachment, "filename", ""))
    suffix = Path(filename).suffix
    return content_type.startswith("video/") or suffix in VIDEO_EXTENSIONS


def is_audio_attachment(attachment) -> bool:
    content_type = normalize_text(getattr(attachment, "content_type", ""))
    filename = normalize_text(getattr(attachment, "filename", ""))
    suffix = Path(filename).suffix
    return content_type.startswith("audio/") or suffix in AUDIO_EXTENSIONS


def attachment_label(attachment) -> str:
    filename = getattr(attachment, "filename", None) or "attachment"
    url = getattr(attachment, "url", None) or getattr(attachment, "proxy_url", None)
    if url:
        return f"[{filename}]({url})"
    return f"`{filename}`"


def attachment_lines(message) -> list[str]:
    return [attachment_label(attachment) for attachment in getattr(message, "attachments", [])]


def media_urls_from_message(message) -> list[str]:
    urls = []
    seen = set()

    def add_url(url: str) -> None:
        if url and url not in seen:
            seen.add(url)
            urls.append(url)

    for embed in getattr(message, "embeds", []):
        for name in ("image", "thumbnail", "video"):
            media = getattr(embed, name, None)
            for attr in ("proxy_url", "url"):
                url = getattr(media, attr, None)
                add_url(url)

        embed_url = getattr(embed, "url", None)
        suffix = suffix_from_url(embed_url or "")
        if suffix in IMAGE_EXTENSIONS or suffix in VIDEO_EXTENSIONS or suffix in AUDIO_EXTENSIONS:
            add_url(embed_url)

    return urls


def embed_text_from_message(message) -> list[str]:
    chunks = []

    def add(value) -> None:
        if value:
            chunks.append(str(value))

    for embed in getattr(message, "embeds", []):
        for attr in ("title", "description", "url"):
            add(getattr(embed, attr, None))

        author = getattr(embed, "author", None)
        for attr in ("name", "url"):
            add(getattr(author, attr, None))

        footer = getattr(embed, "footer", None)
        add(getattr(footer, "text", None))

        for field in getattr(embed, "fields", []) or []:
            add(getattr(field, "name", None))
            add(getattr(field, "value", None))

    return chunks


def suffix_from_url(url: str) -> str:
    return Path(urlparse(str(url)).path.lower()).suffix


async def read_capped(response, limit: int) -> bytes:

    data = bytearray()
    async for chunk in response.content.iter_chunked(DOWNLOAD_CHUNK_BYTES):
        data.extend(chunk)
        if len(data) >= limit:
            break
    return bytes(data)


class ForwardedAttachment:


    def __init__(self, data: dict) -> None:
        self.filename = data.get("filename", "") or ""
        self.content_type = data.get("content_type", "") or ""
        try:
            self.size = int(data.get("size", 0) or 0)
        except (TypeError, ValueError):
            self.size = 0
        self.url = data.get("url", "") or ""
        self.proxy_url = data.get("proxy_url", "") or self.url

    async def read(self) -> bytes:
        url = self.url or self.proxy_url
        if not url:
            return b""
        try:
            import aiohttp
        except ImportError:
            return b""

        timeout = aiohttp.ClientTimeout(total=HTTP_TIMEOUT_SECONDS)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=REQUEST_HEADERS) as response:
                    if response.status >= 400:
                        return b""
                    return await read_capped(response, MAX_VIDEO_SCAN_BYTES + 1)
        except Exception:
            return b""


@dataclass(frozen=True)
class ForwardedSource:
    content: str
    attachments: tuple
    embeds: tuple


def parse_forwarded_sources(raw: dict) -> list["ForwardedSource"]:

    sources: list[ForwardedSource] = []
    for snapshot in raw.get("message_snapshots") or []:
        snapshot_message = snapshot.get("message") or {}
        content = snapshot_message.get("content") or ""

        attachments = tuple(
            ForwardedAttachment(attachment)
            for attachment in snapshot_message.get("attachments") or []
        )

        embeds = []
        for embed_data in snapshot_message.get("embeds") or []:
            try:
                embeds.append(nextcord.Embed.from_dict(embed_data))
            except Exception:
                continue

        if content.strip() or attachments or embeds:
            sources.append(
                ForwardedSource(content=content, attachments=attachments, embeds=tuple(embeds))
            )

    return sources


def get_rapid_ocr():
    global _rapid_ocr, _rapid_ocr_unavailable
    if _rapid_ocr_unavailable:
        return None
    if _rapid_ocr is not None:
        return _rapid_ocr

    try:
        from rapidocr_onnxruntime import RapidOCR
    except ImportError:
        _rapid_ocr_unavailable = True
        return None

    try:
        _rapid_ocr = RapidOCR()
    except Exception:
        _rapid_ocr_unavailable = True
        return None

    return _rapid_ocr


def get_nude_detector():
    global _nude_detector, _nude_detector_unavailable
    if _nude_detector_unavailable:
        return None
    if _nude_detector is not None:
        return _nude_detector

    try:
        from nudenet import NudeDetector
    except ImportError:
        _nude_detector_unavailable = True
        return None

    try:
        _nude_detector = NudeDetector()
    except Exception:
        _nude_detector_unavailable = True
        return None

    return _nude_detector


def extract_text_with_rapidocr(data: bytes) -> str:
    engine = get_rapid_ocr()
    if engine is None:
        return ""

    try:
        result, _ = engine(data)
    except Exception:
        return ""

    if not result:
        return ""

    lines = []
    for item in result:
        if len(item) < 3:
            continue
        text = str(item[1] or "").strip()
        try:
            confidence = float(item[2])
        except (TypeError, ValueError):
            confidence = 0
        if text and confidence >= OCR_CONFIDENCE_THRESHOLD:
            lines.append(text)

    return "\n".join(lines)


def add_text_part(parts: list[str], seen: set[str], text: str) -> None:
    for line in str(text or "").splitlines():
        clean = line.strip()
        key = normalize_text(clean)
        if clean and key not in seen:
            seen.add(key)
            parts.append(clean)


def image_to_jpeg_bytes(image) -> bytes:
    rgb = image.convert("RGB")


    try:
        from PIL import Image

        width, height = rgb.size
        longest = max(width, height)
        if 0 < longest < OCR_UPSCALE_TARGET:
            scale = OCR_UPSCALE_TARGET / longest
            rgb = rgb.resize((int(width * scale), int(height * scale)), Image.LANCZOS)
    except Exception:
        pass

    output = BytesIO()
    rgb.save(output, format="JPEG", quality=92)
    return output.getvalue()


def _flatten_frame(frame):
    from PIL import Image

    rgba = frame.convert("RGBA")
    background = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
    return Image.alpha_composite(background, rgba).convert("RGB")


def sample_image_frames(data: bytes):
    try:
        from PIL import Image, ImageSequence
    except ImportError:
        return []

    try:
        image = Image.open(BytesIO(data))
    except Exception:
        return []

    try:
        frame_count = int(getattr(image, "n_frames", 1) or 1)
    except Exception:
        frame_count = 1

    if frame_count <= 1:
        try:
            return [_flatten_frame(image)]
        except Exception:
            return []

    if frame_count <= MAX_OCR_FRAMES:
        target_indexes = set(range(frame_count))
    else:
        target_indexes = {
            int(index * (frame_count - 1) / max(1, MAX_OCR_FRAMES - 1))
            for index in range(MAX_OCR_FRAMES)
        }

    frames = []
    last_index = max(target_indexes) if target_indexes else 0
    try:
        for index, frame in enumerate(ImageSequence.Iterator(image)):
            if index in target_indexes:
                try:
                    frames.append(_flatten_frame(frame))
                except Exception:
                    pass
            if index >= last_index:
                break
    except Exception:
        pass

    if not frames:
        try:
            frames = [_flatten_frame(image)]
        except Exception:
            frames = []

    return frames


def detect_nsfw_with_nudenet(data: bytes) -> tuple[str, ...]:
    detector = get_nude_detector()
    if detector is None:
        return ()

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as temp_file:
            temp_file.write(data)
            temp_path = temp_file.name

        detections = detector.detect(temp_path)
    except Exception:
        return ()
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass

    unsafe = []
    for detection in detections or []:
        label = normalize_text(detection.get("class", "")).upper().replace(" ", "_")
        try:
            score = float(detection.get("score", 0))
        except (TypeError, ValueError):
            score = 0

        if label in NSFW_CLASSES and score >= NSFW_SCORE_THRESHOLD:
            unsafe.append(f"{label} ({score:.2f})")

    return tuple(unsafe)


def detect_nsfw_from_image_bytes(data: bytes) -> tuple[str, ...]:
    detections = list(detect_nsfw_with_nudenet(data))
    seen = set(detections)



    for frame in sample_image_frames(data)[:MAX_NSFW_FRAMES]:
        frame_detections = detect_nsfw_with_nudenet(image_to_jpeg_bytes(frame))
        for detection in frame_detections:
            if detection not in seen:
                seen.add(detection)
                detections.append(detection)

    return tuple(detections)


def extract_text_from_image_bytes(data: bytes) -> tuple[str, bool]:
    text_parts: list[str] = []
    seen_text: set[str] = set()
    has_qr = False
    rapid_text = extract_text_with_rapidocr(data)
    if rapid_text:
        add_text_part(text_parts, seen_text, rapid_text)

    frames = sample_image_frames(data)
    for frame in frames:
        frame_text = extract_text_with_rapidocr(image_to_jpeg_bytes(frame))
        if frame_text:
            add_text_part(text_parts, seen_text, frame_text)

    try:
        from pyzbar.pyzbar import decode as decode_qr
    except ImportError:
        decode_qr = None

    for frame in frames:
        if decode_qr is not None:
            try:
                decoded = decode_qr(frame)
                if decoded:
                    has_qr = True
                    for code in decoded:
                        data_text = getattr(code, "data", b"")
                        if isinstance(data_text, bytes):
                            data_text = data_text.decode("utf-8", errors="ignore")
                        if data_text:
                            add_text_part(text_parts, seen_text, str(data_text))
            except Exception:
                pass

    return "\n".join(text_parts), has_qr


def scan_video_bytes(data: bytes, suffix: str = ".mp4") -> tuple[str, bool, tuple[str, ...]]:
    try:
        import cv2
    except ImportError:
        return "", False, ()

    temp_path = None
    text_parts: list[str] = []
    has_qr = False
    nsfw_detections: list[str] = []

    try:
        with tempfile.NamedTemporaryFile(suffix=suffix or ".mp4", delete=False) as temp_file:
            temp_file.write(data)
            temp_path = temp_file.name

        capture = cv2.VideoCapture(temp_path)
        if not capture.isOpened():
            return "", False, ()

        frame_count = int(capture.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        if frame_count > 0:
            frame_indexes = [
                int((index + 1) * frame_count / (MAX_VIDEO_FRAMES + 1))
                for index in range(MAX_VIDEO_FRAMES)
            ]
        else:
            frame_indexes = list(range(MAX_VIDEO_FRAMES))

        for frame_index in frame_indexes:
            if frame_index > 0:
                capture.set(cv2.CAP_PROP_POS_FRAMES, frame_index)

            ok, frame = capture.read()
            if not ok:
                continue

            ok, encoded = cv2.imencode(".jpg", frame)
            if not ok:
                continue

            frame_bytes = encoded.tobytes()
            extracted_text, frame_has_qr = extract_text_from_image_bytes(frame_bytes)
            if extracted_text:
                text_parts.append(extracted_text)
            has_qr = has_qr or frame_has_qr
            nsfw_detections.extend(detect_nsfw_with_nudenet(frame_bytes))

        capture.release()
    except Exception:
        return "", False, ()
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass

    return "\n".join(text_parts), has_qr, tuple(nsfw_detections)


def get_ffmpeg_exe() -> str:
    try:
        import imageio_ffmpeg

        return imageio_ffmpeg.get_ffmpeg_exe()
    except Exception:
        return "ffmpeg"


def transcribe_audio_bytes(data: bytes, suffix: str = ".ogg") -> str:
    if not data:
        return ""

    try:
        import speech_recognition as sr
    except Exception:
        return ""

    suffix = suffix if suffix.startswith(".") else f".{suffix}"
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / f"input{suffix or '.ogg'}"
            wav_path = Path(temp_dir) / "audio.wav"
            input_path.write_bytes(data)
            subprocess.run(
                [
                    get_ffmpeg_exe(),
                    "-hide_banner",
                    "-loglevel",
                    "error",
                    "-y",
                    "-t",
                    str(MAX_AUDIO_SECONDS),
                    "-i",
                    str(input_path),
                    "-ac",
                    "1",
                    "-ar",
                    "16000",
                    str(wav_path),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
                timeout=MAX_AUDIO_SECONDS + 20,
            )
            recognizer = sr.Recognizer()
            with sr.AudioFile(str(wav_path)) as source:
                audio = recognizer.record(source, duration=MAX_AUDIO_SECONDS)
            return str(recognizer.recognize_google(audio, language=AUDIO_LANGUAGE)).strip()
    except Exception:
        return ""


def assess_media_bytes(
    data: bytes, suffix: str, *, source: str = ""
) -> tuple[ScamAssessment, str, bool, tuple[str, ...]]:
    suffix = (suffix or "").lower()
    if suffix in VIDEO_EXTENSIONS:
        text, has_qr, nsfw = scan_video_bytes(data, suffix or ".mp4")
        kind = "video"
    elif suffix in AUDIO_EXTENSIONS:
        text = transcribe_audio_bytes(data, suffix or ".ogg")
        has_qr = False
        nsfw = ()
        kind = "audio"
    else:
        text, has_qr = extract_text_from_image_bytes(data)
        nsfw = detect_nsfw_from_image_bytes(data)
        kind = "image"

    parts = [part for part in (source, text) if part]
    assessment = assess_scam_text(
        "\n".join(parts),
        has_qr=has_qr,
        has_media=True,
        nsfw_detections=nsfw,
        content_kind=kind,
    )
    return assessment, text, has_qr, nsfw


class SafetyBot(commands.Bot):
    def __init__(self) -> None:
        intents = nextcord.Intents.default()
        intents.guilds = True
        intents.messages = True
        intents.message_content = True
        self.alerted_message_ids: "OrderedDict[int, None]" = OrderedDict()



        self._processing_ids: set = set()
        self._scan_semaphore = asyncio.Semaphore(SCAN_CONCURRENCY)
        self._heartbeat_task = None

        self._invite_cache: "OrderedDict[str, tuple]" = OrderedDict()
        super().__init__(command_prefix="!", intents=intents)

    async def on_ready(self) -> None:
        scope = (
            "ALL channels"
            if not ALLOWED_CHANNEL_IDS
            else f"channels {sorted(ALLOWED_CHANNEL_IDS)}"
        )
        log.info(
            "Logged in as %s | watching %s | scan concurrency=%d | flag_all_invites=%s",
            self.user,
            scope,
            SCAN_CONCURRENCY,
            FLAG_ALL_INVITES,
        )


        if self._heartbeat_task is None or self._heartbeat_task.done():
            self._heartbeat_task = self.loop.create_task(self._heartbeat_loop())

    async def _heartbeat_loop(self) -> None:



        while not self.is_closed():
            try:
                await asyncio.sleep(HEARTBEAT_LOG_INTERVAL)
                latency = self.latency
                latency_ms = latency * 1000 if latency == latency else float("nan")
                log.info(
                    "alive | latency=%.0fms | alerted_cache=%d",
                    latency_ms,
                    len(self.alerted_message_ids),
                )
            except asyncio.CancelledError:
                break
            except Exception:

                pass

    async def on_error(self, event_method: str, *args, **kwargs) -> None:


        log.exception("Unhandled error in event %s", event_method)

    def _mark_alerted(self, message_id: Optional[int]) -> None:
        if message_id is None:
            return
        self.alerted_message_ids[message_id] = None
        while len(self.alerted_message_ids) > MAX_ALERTED_IDS:
            self.alerted_message_ids.popitem(last=False)

    async def scan_attachment(self, attachment) -> tuple[str, bool, tuple[str, ...]]:
        if not is_visual_attachment(attachment):
            return "", False, ()

        size = getattr(attachment, "size", 0) or 0
        if size > MAX_SCAN_BYTES:
            return "", False, ()

        try:
            data = await attachment.read()
        except (nextcord.HTTPException, AttributeError):
            return "", False, ()

        extracted_text, has_qr = await asyncio.to_thread(extract_text_from_image_bytes, data)
        nsfw_detections = await asyncio.to_thread(detect_nsfw_from_image_bytes, data)
        return extracted_text, has_qr, nsfw_detections

    async def scan_video_attachment(self, attachment) -> tuple[str, bool, tuple[str, ...]]:
        if not is_video_attachment(attachment):
            return "", False, ()

        size = getattr(attachment, "size", 0) or 0
        if size > MAX_VIDEO_SCAN_BYTES:
            return "", False, ()

        try:
            data = await attachment.read()
        except (nextcord.HTTPException, AttributeError):
            return "", False, ()

        suffix = Path(normalize_text(getattr(attachment, "filename", ""))).suffix or ".mp4"
        return await asyncio.to_thread(scan_video_bytes, data, suffix)

    async def scan_audio_attachment(self, attachment) -> tuple[str, bool, tuple[str, ...]]:
        if not is_audio_attachment(attachment):
            return "", False, ()

        size = getattr(attachment, "size", 0) or 0
        if size > MAX_AUDIO_SCAN_BYTES:
            return "", False, ()

        try:
            data = await attachment.read()
        except (nextcord.HTTPException, AttributeError):
            return "", False, ()

        suffix = Path(normalize_text(getattr(attachment, "filename", ""))).suffix or ".ogg"
        text = await asyncio.to_thread(transcribe_audio_bytes, data, suffix)
        return text, False, ()

    async def scan_media_url(self, url: str) -> tuple[str, bool, tuple[str, ...], str]:
        try:
            import aiohttp
        except ImportError:
            return "", False, (), "image"

        timeout = aiohttp.ClientTimeout(total=HTTP_TIMEOUT_SECONDS)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=REQUEST_HEADERS) as response:
                    if response.status >= 400:
                        return "", False, (), "image"
                    content_type = normalize_text(response.headers.get("content-type", ""))
                    suffix = suffix_from_url(url)
                    is_audio = content_type.startswith("audio/") or suffix in AUDIO_EXTENSIONS
                    is_video = (not is_audio) and (content_type.startswith("video/") or suffix in VIDEO_EXTENSIONS)
                    limit = MAX_AUDIO_SCAN_BYTES if is_audio else (MAX_VIDEO_SCAN_BYTES if is_video else MAX_SCAN_BYTES)
                    data = await read_capped(response, limit + 1)
        except Exception:
            return "", False, (), "image"

        if len(data) > limit:
            return "", False, (), "audio" if is_audio else ("video" if is_video else "image")

        if is_audio:
            suffix = suffix_from_url(url) or ".ogg"
            text = await asyncio.to_thread(transcribe_audio_bytes, data, suffix)
            return text, False, (), "audio"

        if is_video:
            suffix = suffix_from_url(url) or ".mp4"
            text, has_qr, detections = await asyncio.to_thread(scan_video_bytes, data, suffix)
            return text, has_qr, detections, "video"

        text, has_qr = await asyncio.to_thread(extract_text_from_image_bytes, data)
        detections = await asyncio.to_thread(detect_nsfw_from_image_bytes, data)
        return text, has_qr, detections, "image"

    async def fetch_forwarded_sources(self, message: nextcord.Message) -> list[ForwardedSource]:


        if getattr(message, "reference", None) is None:
            return []

        channel_id = getattr(getattr(message, "channel", None), "id", None)
        message_id = getattr(message, "id", None)
        if channel_id is None or message_id is None:
            return []



        try:
            raw = await asyncio.wait_for(
                self.http.get_message(channel_id, message_id), timeout=HTTP_TIMEOUT_SECONDS
            )
            return parse_forwarded_sources(raw)
        except Exception:
            return []

    async def resolve_invite(self, code: str) -> Optional[ScamAssessment]:




        now = time.monotonic()
        cached = self._invite_cache.get(code)
        if cached is not None and cached[0] > now:
            self._invite_cache.move_to_end(code)
            return cached[1]

        try:
            result = await asyncio.wait_for(
                self._resolve_invite_uncached(code), timeout=INVITE_RESOLVE_TIMEOUT
            )
        except asyncio.TimeoutError:
            log.warning("invite resolve timed out for %s", code)
            result = None
        except Exception:
            log.exception("invite resolve failed for %s", code)
            result = None



        ttl = INVITE_CACHE_TTL if result is not None else min(60, INVITE_CACHE_TTL)
        self._invite_cache[code] = (now + ttl, result)
        self._invite_cache.move_to_end(code)
        while len(self._invite_cache) > INVITE_CACHE_MAX:
            self._invite_cache.popitem(last=False)
        return result

    async def _resolve_invite_uncached(self, code: str) -> Optional[ScamAssessment]:
        try:
            data = await self.http.get_invite(code, with_counts=True, with_expiration=True)
        except (nextcord.NotFound, nextcord.Forbidden, nextcord.HTTPException, AttributeError):
            return None

        guild = (data or {}).get("guild") or {}
        return assess_invite_guild(
            guild.get("name") or "",
            guild.get("description") or "",
            nsfw_level=guild.get("nsfw_level"),
            nsfw_flag=bool(guild.get("nsfw")),
        )

    async def build_invite_assessment(self, code: str) -> Optional[ScamAssessment]:
        if is_allowed_invite_code(code):
            return None
        return apply_invite_policy(code, await self.resolve_invite(code))

    async def assess_message(
        self, message: nextcord.Message
    ) -> tuple[Optional[ScamAssessment], list[ForwardedSource]]:
        forwarded_sources = await self.fetch_forwarded_sources(message)
        sources = [message, *forwarded_sources]

        visual_attachments: list = []
        video_attachments: list = []
        audio_attachments: list = []
        media_urls: list[str] = []
        seen_urls: set[str] = set()
        text_chunks: list[str] = []

        for source in sources:
            for attachment in getattr(source, "attachments", []) or []:
                if is_visual_attachment(attachment):
                    visual_attachments.append(attachment)
                elif is_video_attachment(attachment):
                    video_attachments.append(attachment)
                elif is_audio_attachment(attachment):
                    audio_attachments.append(attachment)
            for url in media_urls_from_message(source):
                if url not in seen_urls:
                    seen_urls.add(url)
                    media_urls.append(url)
            content = getattr(source, "content", "") or ""
            if content.strip():
                text_chunks.append(content)
            text_chunks.extend(embed_text_from_message(source))

        has_media = bool(visual_attachments or video_attachments or audio_attachments or media_urls)

        message_text = "\n".join(text_chunks)
        text_invite_assessment = first_invite_link_assessment(message_text)
        if text_invite_assessment is not None:
            return text_invite_assessment, forwarded_sources

        media_text_parts: list[str] = []
        has_qr = False
        nsfw_detections = []
        content_kind = (
            "audio"
            if audio_attachments and not visual_attachments and not video_attachments
            else ("video" if video_attachments and not visual_attachments else "image")
        )



        for attachment in visual_attachments:
            media_text_parts.append(getattr(attachment, "filename", ""))
            try:
                extracted_text, attachment_has_qr, attachment_nsfw_detections = await self.scan_attachment(attachment)
            except Exception:
                log.exception("scan_attachment failed; skipping one image")
                continue
            if extracted_text:
                media_text_parts.append(extracted_text)
            has_qr = has_qr or attachment_has_qr
            nsfw_detections.extend(attachment_nsfw_detections)

        for attachment in video_attachments:
            media_text_parts.append(getattr(attachment, "filename", ""))
            try:
                extracted_text, attachment_has_qr, attachment_nsfw_detections = await self.scan_video_attachment(attachment)
            except Exception:
                log.exception("scan_video_attachment failed; skipping one video")
                continue
            if extracted_text:
                media_text_parts.append(extracted_text)
            has_qr = has_qr or attachment_has_qr
            nsfw_detections.extend(attachment_nsfw_detections)

        for attachment in audio_attachments:
            media_text_parts.append(getattr(attachment, "filename", ""))
            try:
                extracted_text, attachment_has_qr, attachment_nsfw_detections = await self.scan_audio_attachment(attachment)
            except Exception:
                log.exception("scan_audio_attachment failed; skipping one audio file")
                continue
            if extracted_text:
                media_text_parts.append(extracted_text)
            has_qr = has_qr or attachment_has_qr
            nsfw_detections.extend(attachment_nsfw_detections)

        for url in media_urls:
            media_text_parts.append(url)
            try:
                extracted_text, url_has_qr, url_nsfw_detections, url_kind = await self.scan_media_url(url)
            except Exception:
                log.exception("scan_media_url failed; skipping one url")
                continue
            if extracted_text:
                media_text_parts.append(extracted_text)
            has_qr = has_qr or url_has_qr
            nsfw_detections.extend(url_nsfw_detections)
            if url_kind == "video":
                content_kind = "video"
            elif url_kind == "audio" and content_kind == "image":
                content_kind = "audio"

        assessments = []
        if message_text.strip():
            assessments.append(
                assess_scam_text(
                    message_text,
                    has_media=False,
                    content_kind="text",
                )
            )

        if has_media:
            assessments.append(
                assess_scam_text(
                    "\n".join(media_text_parts),
                    has_qr=has_qr,
                    has_media=True,
                    nsfw_detections=nsfw_detections,
                    content_kind=content_kind,
                )
            )

        try:
            invite_codes = extract_invite_codes(
                "\n".join([message_text, *media_text_parts])
            )[:MAX_INVITES_PER_MESSAGE]
        except Exception:
            invite_codes = []
        for code in invite_codes:
            invite_assessment = await self.build_invite_assessment(code)
            if invite_assessment is not None:
                assessments.append(invite_assessment)

        alert_assessments = [assessment for assessment in assessments if assessment.should_alert]
        if not alert_assessments:
            return None, forwarded_sources
        return max(alert_assessments, key=lambda assessment: assessment.score), forwarded_sources

    def build_alert_embed(
        self,
        message: nextcord.Message,
        assessment: ScamAssessment,
        forwarded_sources: Iterable[ForwardedSource] = (),
    ) -> nextcord.Embed:
        original_content = getattr(message, "content", "") or ""
        forwarded_sources = list(forwarded_sources)
        is_forwarded = bool(forwarded_sources)
        author = getattr(message, "author", None)
        author_id = getattr(author, "id", "unknown")
        author_mention = getattr(author, "mention", str(author_id))
        channel_mention = getattr(getattr(message, "channel", None), "mention", "unknown channel")

        embed = nextcord.Embed(
            title="Possible Unsafe Forwarded Message Detected"
            if is_forwarded
            else "Possible Unsafe Message Detected",
            description="The original message was not deleted.",
            color=nextcord.Color.orange(),
        )
        embed.add_field(name="User", value=f"{author_mention} (`{author_id}`)", inline=False)
        embed.add_field(name="Channel", value=channel_mention, inline=True)
        embed.add_field(name="Score", value=f"{assessment.score}/100", inline=True)
        embed.add_field(name="Reasons", value=clip("\n".join(f"- {reason}" for reason in assessment.reasons), 1000), inline=False)

        if original_content:
            embed.add_field(name="Original Text", value=clip(original_content, 1000), inline=False)

        if is_forwarded:
            forwarded_text = "\n".join(
                source.content for source in forwarded_sources if getattr(source, "content", "").strip()
            )
            if forwarded_text:
                embed.add_field(name="Forwarded Text", value=clip(forwarded_text, 1000), inline=False)

        if assessment.scanned_text and assessment.content_kind != "text":
            embed.add_field(name="Scanned Text", value=clip(f"`{assessment.scanned_text}`", 1000), inline=False)

        jump_url = getattr(message, "jump_url", None)
        if jump_url:
            embed.add_field(name="Message", value=f"[Jump to message]({jump_url})", inline=False)

        attachment_labels = attachment_lines(message)
        for source in forwarded_sources:
            for attachment in getattr(source, "attachments", []) or []:
                attachment_labels.append(attachment_label(attachment))
            for url in media_urls_from_message(source):
                attachment_labels.append(f"<{url}>")
        if attachment_labels:
            label_name = "Forwarded Attachments" if is_forwarded else "Attachments"
            embed.add_field(name=label_name, value=clip("\n".join(attachment_labels), 1000), inline=False)

        return embed

    async def handle_message(self, message: nextcord.Message) -> None:


        try:
            await self._handle_message(message)
        except Exception:
            log.exception("scan error while handling a message")

    async def _handle_message(self, message: nextcord.Message) -> None:
        if getattr(message, "guild", None) is None:
            return

        author = getattr(message, "author", None)
        if getattr(author, "bot", False):
            return

        if has_moderation_bypass_role(author):
            return

        message_id = getattr(message, "id", None)

        channel = getattr(message, "channel", None)
        if not is_watched_channel(getattr(channel, "id", None)):
            return




        if message_id is not None:
            if message_id in self.alerted_message_ids or message_id in self._processing_ids:
                return
            self._processing_ids.add(message_id)

        try:
            try:
                async with self._scan_semaphore:
                    assessment, forwarded_sources = await asyncio.wait_for(
                        self.assess_message(message), timeout=SCAN_TIMEOUT_SECONDS
                    )
            except asyncio.TimeoutError:
                log.warning("scan timed out for message %s", message_id)
                return

            if assessment is None:
                return

            try:
                await message.channel.send(
                    content=ALERT_MESSAGE,
                    embed=self.build_alert_embed(message, assessment, forwarded_sources),
                    allowed_mentions=nextcord.AllowedMentions(users=True, roles=False, everyone=False),
                )
                self._mark_alerted(message_id)
            except (nextcord.Forbidden, nextcord.HTTPException):
                pass
        finally:


            self._processing_ids.discard(message_id)

    async def on_message(self, message: nextcord.Message) -> None:
        await self.handle_message(message)

    async def on_message_edit(self, before: nextcord.Message, after: nextcord.Message) -> None:
        await self.handle_message(after)

    async def on_raw_message_edit(self, payload: nextcord.RawMessageUpdateEvent) -> None:
        try:
            if not is_watched_channel(payload.channel_id):
                return

            if payload.message_id in self.alerted_message_ids:
                return

            await asyncio.sleep(1)

            channel = self.get_channel(payload.channel_id)
            if channel is None:
                try:
                    channel = await self.fetch_channel(payload.channel_id)
                except (nextcord.Forbidden, nextcord.HTTPException):
                    return

            try:
                message = await channel.fetch_message(payload.message_id)
            except (AttributeError, nextcord.Forbidden, nextcord.NotFound, nextcord.HTTPException):
                return

            await self.handle_message(message)
        except Exception:
            log.exception("error in on_raw_message_edit")


def fetch_target_bytes(target: str) -> tuple[bytes, str]:
    parsed = urlparse(target)
    if parsed.scheme in ("http", "https"):
        import urllib.request

        request = urllib.request.Request(target, headers=REQUEST_HEADERS)
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            data = response.read()
            content_type = normalize_text(response.headers.get("content-type", ""))
        suffix = suffix_from_url(target)
        if not suffix:
            if content_type.startswith("audio/"):
                suffix = ".ogg"
            elif content_type.startswith("video/"):
                suffix = ".mp4"
            elif "gif" in content_type:
                suffix = ".gif"
            elif content_type.startswith("image/"):
                suffix = ".png"
        return data, suffix

    path = Path(target).expanduser()
    return path.read_bytes(), path.suffix


def _print_assessment(assessment: ScamAssessment) -> None:
    verdict = "DANGEROUS — would alert" if assessment.should_alert else "safe — no alert"
    print("--- assessment ---")
    print(f"score:   {assessment.score}/100  (alert threshold {ALERT_THRESHOLD})")
    print(f"verdict: {verdict}")
    if assessment.reasons:
        print("reasons:")
        for reason in assessment.reasons:
            print(f"  - {reason}")


def fetch_invite_guild(code: str) -> dict:

    import urllib.request

    url = f"https://discord.com/api/v10/invites/{code}?with_counts=true&with_expiration=true"
    request = urllib.request.Request(url, headers=REQUEST_HEADERS)
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        payload = json.loads(response.read().decode("utf-8", errors="ignore"))
    return payload if isinstance(payload, dict) else {}


def run_cli(args: list[str]) -> int:
    mode = args[0]

    if mode in ("--text", "-t"):
        text = " ".join(args[1:]).strip()
        if not text:
            print('usage: python bot.py --text "message to score"')
            return 2
        _print_assessment(
            first_invite_link_assessment(text)
            or assess_scam_text(text, has_media=False, content_kind="text")
        )
        return 0

    if mode in ("--invite", "-i"):
        if len(args) < 2:
            print("usage: python bot.py --invite <code-or-url>")
            return 2
        raw = args[1]
        codes = extract_invite_codes(raw) or [raw.rstrip("/").split("/")[-1]]
        code = codes[0]
        print(f"invite code : {code}")
        print(f"FLAG_ALL_INVITES = {FLAG_ALL_INVITES} | INVITE_BASE_SCORE = {INVITE_BASE_SCORE}")
        resolved = None
        try:
            invite = fetch_invite_guild(code)
            guild = invite.get("guild") or {}
            print(f"server name : {guild.get('name')!r}")
            print(f"description : {guild.get('description')!r}")
            print(
                f"nsfw_level  : {guild.get('nsfw_level')} "
                f"(0=default, 1=explicit, 2=safe, 3=age-restricted)"
            )
            print(f"nsfw flag   : {guild.get('nsfw')}")
            print(
                f"members     : ~{invite.get('approximate_member_count')} "
                f"({invite.get('approximate_presence_count')} online)"
            )
            resolved = assess_invite_guild(
                guild.get("name") or "",
                guild.get("description") or "",
                nsfw_level=guild.get("nsfw_level"),
                nsfw_flag=bool(guild.get("nsfw")),
            )
        except Exception as error:
            print(f"destination : could NOT be resolved ({error}) — expired/private/unreachable")
        final = apply_invite_policy(code, resolved)
        if final is None:
            print("--- assessment ---")
            print("verdict: safe — no alert (FLAG_ALL_INVITES is off and destination looks clean)")
        else:
            _print_assessment(final)
        return 0

    if len(args) < 2:
        print("usage: python bot.py --scan <path-or-url>")
        return 2

    target = args[1]
    try:
        data, suffix = fetch_target_bytes(target)
    except Exception as error:
        print(f"could not load {target}: {error}")
        return 1

    print(f"loaded {len(data)} bytes from {target} (suffix={suffix or 'unknown'})")
    assessment, text, has_qr, nsfw = assess_media_bytes(data, suffix, source=target)
    if text:
        print("--- extracted text ---")
        print(text)
    else:
        print("--- no text extracted ---")
    if nsfw:
        print(f"explicit-content detections: {', '.join(nsfw)}")
    print(f"QR detected: {has_qr}")
    _print_assessment(assessment)
    return 0


def setup_logging() -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    try:
        handlers.append(RotatingFileHandler(LOG_FILE, maxBytes=5_000_000, backupCount=3))
    except Exception:
        pass
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
    )

    for noisy in ("nextcord", "nextcord.gateway", "nextcord.client", "nextcord.http"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


async def run_supervised(token: str) -> None:

    backoff = RESTART_MIN_BACKOFF
    while True:
        bot = SafetyBot()
        started = time.monotonic()
        try:
            await bot.start(token, reconnect=True)
        except nextcord.LoginFailure:
            log.error(
                "Login failed: SAFETY_BOT_TOKEN is invalid. Fix .env — the bot will keep retrying."
            )
        except nextcord.PrivilegedIntentsRequired:
            log.error(
                "Message Content Intent is OFF in the Discord Developer Portal. "
                "Enable it under your application's Bot settings — the bot will keep retrying."
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            log.exception("Bot stopped with an unexpected error; restarting.")
        else:
            log.warning("Bot connection closed; restarting.")
        finally:
            try:
                if not bot.is_closed():
                    await bot.close()
            except Exception:
                pass



        if time.monotonic() - started > 60:
            backoff = RESTART_MIN_BACKOFF
        log.info("restarting in %.0fs", backoff)
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, RESTART_MAX_BACKOFF)


def main() -> None:
    argv = sys.argv[1:]
    if argv and argv[0] in ("--scan", "-s", "--text", "-t", "--invite", "-i"):
        raise SystemExit(run_cli(argv))

    setup_logging()
    token = (os.environ.get("SAFETY_BOT_TOKEN") or "").strip()
    if not token:
        log.error(
            "SAFETY_BOT_TOKEN is not set. Copy .env.example to .env and add the bot token."
        )
        raise SystemExit(2)

    log.info("Starting safety bot supervisor (auto-restart enabled).")
    try:
        asyncio.run(run_supervised(token))
    except (KeyboardInterrupt, SystemExit):
        log.info("Shutting down (stop signal received).")


if __name__ == "__main__":
    main()
