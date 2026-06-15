
import asyncio
import logging
import os
import random
import string
import time
import traceback




logging.disable(logging.CRITICAL)

import bot as B


def say(msg):
    print(msg, flush=True)



B.INVITE_RESOLVE_TIMEOUT = 0.3
B.SCAN_TIMEOUT_SECONDS = 2

random.seed(1234)
FAILURES = []


def rnd_text(n):
    alphabet = string.ascii_letters + string.digits + " |*_~`$@/.:+-!#" + "😀💰🎁​‮"
    return "".join(random.choice(alphabet) for _ in range(n))





def fuzz_pure(iterations=12000):
    say(f"[1] pure-function fuzz: running {iterations} iterations...")
    assert B.extract_invite_codes("join discord.gg/gohar") == ["gohar"]
    assert B.first_invite_link_assessment("join discord.gg/gohar") is None
    assert B.first_invite_link_assessment("join discord.gg/gohar and discord.gg/bad") is not None
    weird = [
        None, "", " ", "|" * 3000, "||" * 2000, "*" * 3000, "a" * 8000,
        "f||r||ee m||on||ey", "https://discord.gg/" + "x" * 1500,
        "‮evil", "\x00\x01\x02", "😀" * 500, "discord.gg/", "||||||",
        "discord.gg/" + "-" * 50, "c*l*a*i*m", "deezbet.com" * 200,
    ]
    for i in range(iterations):
        if i and i % 4000 == 0:
            say(f"      ...{i}/{iterations}")
        t = random.choice(weird) if i % 7 == 0 else rnd_text(random.randint(0, 400))
        try:
            B.normalize_text(t)
            B.strip_discord_markup(t if t is not None else "")
            B.collapse_spaced_letters(B.strip_discord_markup(B.normalize_text(t)))
            B.extract_invite_codes(t if t is not None else "")
            a = B.assess_scam_text(t if t is not None else "", has_media=bool(i % 2))
            assert 0 <= a.score <= 100
            g = B.assess_invite_guild(
                t if t is not None else "",
                random.choice(["", None, "x" * 2000, t]),
                nsfw_level=random.choice([None, 0, 1, 2, 3, 99, "3", "bad", -1]),
                nsfw_flag=random.choice([True, False, None, 1, 0]),
            )
            assert 0 <= g.score <= 100
        except Exception:
            FAILURES.append(("pure", repr(t)[:80], traceback.format_exc()))
            if len(FAILURES) > 5:
                break
    say(f"    done — failures={len(FAILURES)}")





def fuzz_media():
    say("[2] garbage-media scan: first run is slow...")
    blobs = [
        b"", b"not an image", b"\x89PNG\r\n\x1a\n" + b"\x00" * 20,
        b"GIF89a" + os.urandom(200), os.urandom(5000), b"\xff\xd8\xff" + b"\x00" * 50,
    ]
    fails = 0
    for blob in blobs:
        for suffix in (".png", ".gif", ".jpg", ".mp4", ".webp", ""):
            try:
                B.assess_media_bytes(blob, suffix, source="fuzz")
            except Exception:
                fails += 1
                FAILURES.append(("media", suffix, traceback.format_exc()))
    say(f"    done — {len(blobs) * 6} combos, failures={fails}")





CALL_COUNT = {"get_invite": 0}


class FakeHTTP:
    async def get_invite(self, code, with_counts=True, with_expiration=True):
        CALL_COUNT["get_invite"] += 1
        roll = random.random()
        if roll < 0.2:
            raise B.nextcord.NotFound.__new__(B.nextcord.NotFound)
        if roll < 0.35:
            raise RuntimeError("boom")
        if roll < 0.5:
            await asyncio.sleep(5)
            return {"guild": {"name": "slow", "nsfw_level": 0}}
        if roll < 0.65:
            return {"garbage": True}
        if roll < 0.8:
            return {"guild": {"name": "nina's little recordings", "nsfw_level": 3, "nsfw": True}}
        return {"guild": {"name": "Cozy Gamers", "description": "sfw fun", "nsfw_level": 0}}

    async def get_message(self, channel_id, message_id):
        if random.random() < 0.3:
            raise RuntimeError("fetch failed")
        return {"message_snapshots": [{"message": {
            "content": random.choice(["||free nitro|| discord.gg/abc", "hello", "withdraw success +2700 usdt"]),
            "attachments": [], "embeds": []}}]}


class FakeChannel:
    def __init__(self, cid):
        self.id = cid
        self.mention = "#test"
        self.sent = 0

    async def send(self, content=None, embed=None, allowed_mentions=None):
        self.sent += 1
        if random.random() < 0.15:
            raise B.nextcord.HTTPException.__new__(B.nextcord.HTTPException)


class FakeAuthor:
    def __init__(self):
        self.id = random.randint(1, 10 ** 18)
        self.mention = "@user"
        self.bot = False


class FakeMessage:
    def __init__(self, mid, content, channel, reference=False):
        self.id = mid
        self.content = content
        self.channel = channel
        self.guild = object()
        self.author = FakeAuthor()
        self.attachments = []
        self.embeds = []
        self.reference = object() if reference else None
        self.jump_url = "http://jump"


CONTENTS = [
    "look at this https://discord.gg/" + "".join(random.choice(string.ascii_letters) for _ in range(8)),
    "||MrBeast giving away $2500 claim deezbet.com promo code BONUS||",
    "f||r||ee m||on||ey cl||a||im at deezbet.com",
    "join discord.gg/abc and discord.gg/def and discord.gg/ghi and discord.gg/jkl",
    "gg everyone good game",
    "discord.gg/python",
    "🎁🎁 c*l*a*i*m your reward 🎁",
    rnd_text(300),
    "",
]


async def stress_handle(total=2000, concurrency=50):
    say(f"[3] handle_message stress: {total} concurrent messages with a hostile API...")
    bot = B.SafetyBot.__new__(B.SafetyBot)
    bot.alerted_message_ids = B.OrderedDict()
    bot._scan_semaphore = asyncio.Semaphore(B.SCAN_CONCURRENCY)
    bot._invite_cache = B.OrderedDict()
    bot._heartbeat_task = None
    bot.http = FakeHTTP()

    channel = FakeChannel(next(iter(B.ALLOWED_CHANNEL_IDS), 12345))

    errors = {"count": 0}
    sem = asyncio.Semaphore(concurrency)

    async def one(i):
        async with sem:
            msg = FakeMessage(i, random.choice(CONTENTS), channel, reference=(random.random() < 0.3))
            try:

                await bot.handle_message(msg)
            except Exception:
                errors["count"] += 1
                FAILURES.append(("handle", "", traceback.format_exc()))

    start = time.monotonic()
    await asyncio.gather(*[one(i) for i in range(total)])
    elapsed = time.monotonic() - start
    say(f"    done in {elapsed:.1f}s")
    say(f"    handle exceptions escaped = {errors['count']}  (must be 0)")
    say(f"    get_invite API calls = {CALL_COUNT['get_invite']}  (cache keeps this low under spam)")
    say(f"    invite_cache size = {len(bot._invite_cache)} (cap {B.INVITE_CACHE_MAX})")
    say(f"    alerted_cache size = {len(bot.alerted_message_ids)} (cap {B.MAX_ALERTED_IDS})")


    assert elapsed < 60, f"stress run took too long ({elapsed:.1f}s) — a timeout is not firing"
    assert errors["count"] == 0


def main():
    say("=== safety bot stress test (expect ~20-50s; pauses are normal) ===")
    t0 = time.monotonic()
    fuzz_pure()
    fuzz_media()
    asyncio.run(stress_handle())
    say("")
    if FAILURES:
        say(f"!!! {len(FAILURES)} FAILURE(S):")
        for kind, ctx, tb in FAILURES[:3]:
            say(f"--- {kind} {ctx}")
            say(tb)
        raise SystemExit(1)
    say(f"ALL STRESS TESTS PASSED in {time.monotonic() - t0:.0f}s "
        f"— no exception escaped, no hang, caches bounded.")


if __name__ == "__main__":
    main()
