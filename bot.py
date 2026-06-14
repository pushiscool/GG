from __future__ import annotations

import asyncio
import os
import re
import tempfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Iterable, Optional

import nextcord
from dotenv import load_dotenv
from nextcord.ext import commands


ALERT_USER_ID = 920819377627099166
ALERT_MESSAGE = f"<@{ALERT_USER_ID}>"
ALLOWED_CHANNEL_IDS = {
    1515821430586216468,
    1508284501485162541,
}

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}
VIDEO_EXTENSIONS = {".mp4", ".mov", ".webm", ".m4v", ".mkv"}
MAX_SCAN_BYTES = 8 * 1024 * 1024
MAX_VIDEO_SCAN_BYTES = 32 * 1024 * 1024
MAX_OCR_FRAMES = 3
MAX_VIDEO_FRAMES = 5
OCR_CONFIDENCE_THRESHOLD = 0.45
NSFW_SCORE_THRESHOLD = 0.55

ALERT_THRESHOLD = 70

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
    r"|\d[\d,]*\s*(?:k\b|grand|dollars?|usd|euros?|pounds?|bucks|thousand|million|billion)"
    r"|(?:hundred|thousand|million|billion)\s+(?:dollars?|usd|euros?|pounds?|bucks)"
    r"|\bdollars?\b|\beuros?\b"
    r"|usd|cash(?:\s*app)?|money|gift\s*card|nitro|robux|v-?bucks|crypto|bitcoin|btc|eth|paypal|venmo|zelle)",
    re.IGNORECASE,
)
HANDLE_RE = re.compile(r"@(?:everyone|here|[\w.-]{2,32})", re.IGNORECASE)
DM_LURE_RE = re.compile(
    r"\b(?:dm|dms|pm|pms|msg|message|inbox|hmu|contact|text|add)\s+me\b"
    r"|\bdm\s+(?:me|us)\b"
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
HOOK_RE = re.compile(
    r"\b(?:get|getting|become|becoming)\s+rich\b"
    r"|\brich\s+quick\b"
    r"|\bmake\s+money\s+fast\b"
    r"|\bquick\s+(?:money|cash)\b"
    r"|\bchance\s+to\s+win\b"
    r"|\bwin\s+(?:\$|\d|big|one\s+(?:hundred|thousand|million|billion))",
    re.IGNORECASE,
)
OFF_PLATFORM_RE = re.compile(
    r"\b(?:telegram|whatsapp|whats\s*app|signal|wechat|kik|snapchat|t\.me)\b",
    re.IGNORECASE,
)
BARE_DOMAIN_RE = re.compile(
    r"\b[\w-]{2,}\.(?:com|net|org|io|me|gg|co|app|info|biz|live|online|site|shop|store|vip|win|top|fun|cc|tk|ml|xyz|click|link)\b",
    re.IGNORECASE,
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
    "giving away",
    "give away",
    "handing out",
    "free money",
    "free cash",
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
    normalized = normalize_text(text)
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
    has_bare_domain = bool(BARE_DOMAIN_RE.search(normalized))
    has_url = bool(URL_RE.search(normalized) or SHORTENER_RE.search(normalized) or SUSPICIOUS_DOMAIN_RE.search(normalized))
    has_parody = contains_any(normalized, PARODY_TERMS)
    is_meta_example = bool(META_EXAMPLE_RE.search(normalized))

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

    if has_bare_domain and has_giveaway:
        score += 35
        reasons.append("external website tied to a reward offer")

    if has_off_platform and (has_dm_lure or has_url or has_bare_domain):
        score += 20
        reasons.append("moves users to another app")

    if has_url:
        score += 30
        reasons.append("link or suspicious domain")

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

    score = min(score, 100)

    return ScamAssessment(
        score=score,
        reasons=tuple(reasons),
        scanned_text=clip(text, 500),
        content_kind=content_kind,
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


def attachment_label(attachment) -> str:
    filename = getattr(attachment, "filename", None) or "attachment"
    url = getattr(attachment, "url", None) or getattr(attachment, "proxy_url", None)
    if url:
        return f"[{filename}]({url})"
    return f"`{filename}`"


def attachment_lines(message) -> list[str]:
    return [attachment_label(attachment) for attachment in getattr(message, "attachments", [])]


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


def extract_text_from_image_bytes(data: bytes) -> tuple[str, bool]:
    text_parts: list[str] = []
    has_qr = False
    rapid_text = extract_text_with_rapidocr(data)
    if rapid_text:
        text_parts.append(rapid_text)

    try:
        from PIL import Image, ImageSequence
    except ImportError:
        return "\n".join(text_parts), False

    try:
        image = Image.open(BytesIO(data))
    except Exception:
        return "\n".join(text_parts), False

    frames = []
    try:
        for index, frame in enumerate(ImageSequence.Iterator(image)):
            if index >= MAX_OCR_FRAMES:
                break
            frames.append(frame.convert("RGB"))
    except Exception:
        frames = [image.convert("RGB")]

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
                            text_parts.append(str(data_text))
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


class SafetyBot(commands.Bot):
    def __init__(self) -> None:
        intents = nextcord.Intents.default()
        intents.guilds = True
        intents.messages = True
        intents.message_content = True
        super().__init__(command_prefix="!", intents=intents)

    async def on_ready(self) -> None:
        print(f"Logged in as {self.user}")

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
        nsfw_detections = await asyncio.to_thread(detect_nsfw_with_nudenet, data)
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

    async def assess_message(self, message: nextcord.Message) -> Optional[ScamAssessment]:
        visual_attachments = [
            attachment for attachment in getattr(message, "attachments", []) if is_visual_attachment(attachment)
        ]
        video_attachments = [
            attachment for attachment in getattr(message, "attachments", []) if is_video_attachment(attachment)
        ]
        has_media = bool(visual_attachments or video_attachments)

        message_text = getattr(message, "content", "") or ""
        media_text_parts: list[str] = []
        has_qr = False
        nsfw_detections = []
        content_kind = "video" if video_attachments and not visual_attachments else "image"

        for attachment in visual_attachments:
            media_text_parts.append(getattr(attachment, "filename", ""))
            extracted_text, attachment_has_qr, attachment_nsfw_detections = await self.scan_attachment(attachment)
            if extracted_text:
                media_text_parts.append(extracted_text)
            has_qr = has_qr or attachment_has_qr
            nsfw_detections.extend(attachment_nsfw_detections)

        for attachment in video_attachments:
            media_text_parts.append(getattr(attachment, "filename", ""))
            extracted_text, attachment_has_qr, attachment_nsfw_detections = await self.scan_video_attachment(attachment)
            if extracted_text:
                media_text_parts.append(extracted_text)
            has_qr = has_qr or attachment_has_qr
            nsfw_detections.extend(attachment_nsfw_detections)

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

        alert_assessments = [assessment for assessment in assessments if assessment.should_alert]
        if not alert_assessments:
            return None
        return max(alert_assessments, key=lambda assessment: assessment.score)

    def build_alert_embed(self, message: nextcord.Message, assessment: ScamAssessment) -> nextcord.Embed:
        original_content = getattr(message, "content", "") or ""
        author = getattr(message, "author", None)
        author_id = getattr(author, "id", "unknown")
        author_mention = getattr(author, "mention", str(author_id))
        channel_mention = getattr(getattr(message, "channel", None), "mention", "unknown channel")

        embed = nextcord.Embed(
            title="Possible Unsafe Message Detected",
            description="The original message was not deleted.",
            color=nextcord.Color.orange(),
        )
        embed.add_field(name="User", value=f"{author_mention} (`{author_id}`)", inline=False)
        embed.add_field(name="Channel", value=channel_mention, inline=True)
        embed.add_field(name="Score", value=f"{assessment.score}/100", inline=True)
        embed.add_field(name="Reasons", value=clip("\n".join(f"- {reason}" for reason in assessment.reasons), 1000), inline=False)

        if original_content:
            embed.add_field(name="Original Text", value=clip(original_content, 1000), inline=False)
        if assessment.scanned_text and assessment.content_kind != "text":
            embed.add_field(name="Scanned Text", value=clip(f"`{assessment.scanned_text}`", 1000), inline=False)

        jump_url = getattr(message, "jump_url", None)
        if jump_url:
            embed.add_field(name="Message", value=f"[Jump to message]({jump_url})", inline=False)

        attachments = attachment_lines(message)
        if attachments:
            embed.add_field(name="Attachments", value=clip("\n".join(attachments), 1000), inline=False)

        return embed

    async def on_message(self, message: nextcord.Message) -> None:
        if getattr(message, "guild", None) is None:
            return

        if getattr(getattr(message, "author", None), "bot", False):
            return

        if message.channel.id not in ALLOWED_CHANNEL_IDS:
            return

        assessment = await self.assess_message(message)
        if assessment is None:
            return

        try:
            await message.channel.send(
                content=ALERT_MESSAGE,
                embed=self.build_alert_embed(message, assessment),
                allowed_mentions=nextcord.AllowedMentions(users=True, roles=False, everyone=False),
            )
        except (nextcord.Forbidden, nextcord.HTTPException):
            pass


def main() -> None:
    load_dotenv()
    SafetyBot().run(os.environ["SAFETY_BOT_TOKEN"])


if __name__ == "__main__":
    main()
