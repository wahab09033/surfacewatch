"""Password strength checks.

The rules this replaces were length plus "must contain a letter and a digit",
which is the policy that produces ``password1234`` — 12 characters, both
classes, and somewhere near the top of every breach corpus ever published. A
composition rule cannot tell a strong password from a common one, because the
thing that makes a password weak is that other people chose it too.

So there are two layers here:

*   an offline check (this module), which catches the head of the distribution
    and the structural patterns — keyboard runs, repeats, a dictionary word
    with digits stapled on, and the user's own email/org/domain, and
*   an optional online check against Have I Been Pwned's range API
    (:func:`pwned_count`), which covers the ~850M-entry corpus no bundled list
    can approach.

Both are needed. The offline one because it must work with no network and no
latency, the online one because "not in my 300-word list" is a much weaker
claim than "not in any published breach".
"""

from __future__ import annotations

import hashlib
import logging
import re

logger = logging.getLogger(__name__)

__all__ = ["MIN_LENGTH", "assert_not_breached", "check", "pwned_count"]

MIN_LENGTH = 12
# bcrypt truncates at 72 bytes; silently ignoring the rest of a longer password
# would mean the strength the user thinks they chose is not the strength stored.
MAX_BYTES = 72

# The head of the breach distribution, in base form. Kept as base words rather
# than full passwords because the mutations people apply are predictable and
# _reduce() below strips them: "P@ssw0rd!23" and "password" collapse together,
# so one entry covers a family. Not exhaustive by design — exhaustive is what
# the HIBP layer is for.
_COMMON_RAW = """
password passwd pass secret letmein welcome admin administrator root toor login
logon user username guest test testing demo sample example default changeme
change qwerty qwertyuiop asdf asdfgh asdfghjkl zxcvbn zxcvbnm qazwsx qwe abc
abcd abcde abcdef abcdefg monkey dragon master shadow superman batman spiderman
football baseball basketball soccer hockey tennis golf cricket sunshine princess
flower iloveyou loveyou love lovely forever angel diamond butterfly summer
winter spring autumn january february march april june july august september
october november december monday friday hello helloworld whatever trustno
freedom starwars startrek pokemon minecraft fortnite computer internet
microsoft windows google facebook twitter instagram samsung apple android
linux ubuntu oracle amazon netflix spotify yahoo hotmail gmail school college
university student teacher soccer money cash bank access phoenix ranger hunter
killer ninja hacker matrix trinity neo cheese chocolate cookie pepper ginger
jordan michael jennifer jessica ashley amanda joshua daniel matthew andrew
david john james robert william richard thomas charlie george harry oliver
jack sophie emma olivia liverpool arsenal chelsea barcelona madrid juventus
manchester bayern dallas cowboys yankees lakers surfacewatch scanner security
firewall network server database sysadmin support helpdesk service backup
temporary temp public private secure insecure unknown nothing anything
something nobody somebody everybody princess1 sunshine1 baby angel iloveu
qwerty1 monkey1 dragon1 asshole fuckyou fuckoff bullshit
"""
_COMMON = frozenset(_COMMON_RAW.split())

# Homoglyph substitutions, in the direction that undoes them.
_LEET = str.maketrans(
    {
        "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "6": "g", "7": "t",
        "8": "b", "9": "g", "@": "a", "$": "s", "!": "i", "|": "i", "+": "t",
    }
)

# How much of the password a common word must account for before the password
# counts as "that word with decoration". 0.7 keeps "Limit-P4ssw0rd!" (a
# password containing a mutated common word) while rejecting "P@ssw0rd12"
# (a mutated common word containing nothing else). The line has to fall
# somewhere; this side of it errs toward not blocking real users, since the
# HIBP layer is what makes the strong claim.
_DOMINANCE = 0.7

_KEYBOARD_ROWS = (
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "abcdefghijklmnopqrstuvwxyz",
)


def _reduce(value: str) -> str:
    """Collapse a password to the base a human started from, folding homoglyphs.

    ``P@ssw0rd!2024`` -> ``passwordiea``, whose prefix is ``password``. This is
    what makes a 300-entry list behave like a much larger one: the mutations are
    the predictable part.
    """
    folded = value.lower().translate(_LEET)
    return re.sub(r"[^a-z]", "", folded)


def _strip_non_alpha(value: str) -> str:
    """Drop everything that is not a letter, without folding homoglyphs.

    Needed alongside :func:`_reduce` because leet-folding a trailing digit run
    turns it into letters: ``admin1234567`` reduces to ``adminieasgt``, which
    matches nothing, while stripping gives exactly ``admin``. Digits appended to
    a word and digits substituted inside one are different mutations, and each
    reduction only undoes one of them.
    """
    return re.sub(r"[^a-z]", "", value.lower())


def _bases(value: str) -> tuple[str, ...]:
    """Every plausible base word for ``value``, cheapest comparison first."""
    return tuple({_strip_non_alpha(value), _reduce(value)})


def _adjacent_pairs() -> frozenset[str]:
    """Every two-character step along a keyboard row, in both directions.

    Rows have no repeated characters, so a chunk is a contiguous slice of a row
    exactly when each of its adjacent pairs is one of these steps. That turns
    run detection into a linear walk instead of a substring search.
    """
    pairs: set[str] = set()
    for row in _KEYBOARD_ROWS:
        for text in (row, row[::-1]):
            pairs.update(text[i : i + 2] for i in range(len(text) - 1))
    return frozenset(pairs)


_ADJACENT = _adjacent_pairs()

# Runs shorter than this are coincidence, not a pattern: "as" and "poi" turn up
# inside ordinary words.
_MIN_RUN = 4


def _keyboard_coverage(value: str) -> float:
    """Fraction of the password made up of keyboard or alphabet runs.

    Coverage rather than "is there one long run", because the earlier version
    of this asked whether a *single* run accounted for most of the password —
    and no row is longer than 26 characters, so beyond ~37 characters no run
    could ever qualify and "qwertyuiop...1234567890" repeated twice was
    accepted. Several runs back to back are exactly as guessable as one.
    """
    folded = re.sub(r"[^a-z0-9]", "", value.lower())
    if len(folded) < _MIN_RUN:
        return 0.0

    covered = 0
    run = 1
    for i in range(1, len(folded) + 1):
        step = folded[i - 1 : i + 1]
        if i < len(folded) and len(step) == 2 and step in _ADJACENT:
            run += 1
            continue
        if run >= _MIN_RUN:
            covered += run
        run = 1

    return covered / len(folded)


def _is_keyboard_run(value: str) -> bool:
    """True if the password is mostly keyboard or alphabet sequences."""
    return _keyboard_coverage(value) >= _DOMINANCE


def _distinct_ratio(value: str) -> float:
    return len(set(value)) / len(value) if value else 0.0


def _has_repeated_unit(value: str) -> bool:
    """``abcabcabcabc`` and ``aaaaaaaaaaaa`` are long without being strong."""
    folded = value.lower()
    for size in range(1, len(folded) // 2 + 1):
        unit = folded[:size]
        if unit * (len(folded) // size) == folded[: len(folded) // size * size]:
            if len(folded) // size >= 3:
                return True
    return False


def check(password: str, *, context: tuple[str, ...] = ()) -> str | None:
    """Return a rejection reason, or ``None`` if the password is acceptable.

    ``context`` holds strings the password must not be built from — the user's
    email, organisation name and domain. A password derived from the account it
    protects is guessable by anyone who knows the account exists, which for a
    login form is everyone.

    Returns a message rather than raising so the caller decides how to surface
    it; the messages are written to tell the user what to change without
    lecturing, and never echo the password back.
    """
    if len(password) < MIN_LENGTH:
        return f"Password must be at least {MIN_LENGTH} characters"
    if len(password.encode("utf-8")) > MAX_BYTES:
        return f"Password must be at most {MAX_BYTES} bytes"
    if password != password.strip():
        # Leading/trailing whitespace survives storage but never survives a
        # copy-paste, so it locks people out of their own accounts.
        return "Password must not begin or end with whitespace"

    if _distinct_ratio(password) < 0.3:
        return "Password repeats too few distinct characters"
    if _has_repeated_unit(password):
        return "Password is a short pattern repeated; choose something less predictable"
    if _is_keyboard_run(password):
        return "Password is a keyboard or alphabet sequence; choose something less predictable"

    # Checked against both reductions: digits *substituted into* a word and
    # digits *appended to* one are different mutations, and one reduction only
    # undoes one of them.
    candidates = _bases(password)
    if any(base in _COMMON for base in candidates):
        return "Password is one of the most commonly breached passwords"
    # A common word with a little stapled on is still that word — but only if
    # the word is most of what is there. Matching a bare prefix/suffix at any
    # length would reject "Brand-N3w-Pass!" for ending in "pass", which is a
    # perfectly reasonable password with a four-letter coincidence in it.
    for base in candidates:
        for common in _COMMON:
            if len(common) < 4 or len(common) < len(base) * _DOMINANCE:
                continue
            if base.startswith(common) or base.endswith(common):
                return "Password is based on a commonly breached password"

    # Same dominance test as above, and for the same reason. A bare substring
    # match would reject "my-glacier-vault-42" for an org called Vault Corp —
    # the password is strong and the shared word is a coincidence. What is
    # actually weak is a password that IS the org name with decoration.
    for item in context:
        token = _strip_non_alpha(item)
        if len(token) < 4:
            continue
        for base in candidates:
            if not base:
                continue
            if token == base or (
                token in base and len(token) >= len(base) * _DOMINANCE
            ):
                return "Password must not be based on your name, email, or organisation"

    return None


def pwned_count(password: str, *, timeout: float | None = None) -> int:
    """How many times this password appears in Have I Been Pwned. 0 if clean.

    Uses the k-anonymity range endpoint: only the first five hex characters of
    the SHA-1 leave this process, and the response is a list of ~500-1000
    suffixes matched locally. The full password, and the full hash, never go
    anywhere. SHA-1 here is HIBP's index, not a security decision.

    Returns 0 on any error, i.e. fails open. A registration form that breaks
    when a third-party API is slow is a worse outcome than one that occasionally
    accepts a breached password, and the offline checks in :func:`check` have
    already run regardless.

    Blocking I/O — call it from a threadpool, never directly on the event loop.
    """
    import httpx

    from config import settings

    if timeout is None:
        timeout = settings.password_hibp_timeout

    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324
    prefix, suffix = digest[:5], digest[5:]

    try:
        response = httpx.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=timeout,
            # Pads the response to a uniform size so its *length* does not leak
            # how many suffixes share the prefix.
            headers={"Add-Padding": "true"},
        )
        response.raise_for_status()
    except Exception:
        logger.warning("pwned password lookup failed; allowing", exc_info=True)
        return 0

    for line in response.text.splitlines():
        candidate, _, count = line.partition(":")
        if candidate.strip() == suffix:
            try:
                return int(count)
            except ValueError:
                return 1
    return 0


async def assert_not_breached(password: str) -> None:
    """Raise 400 if HIBP has seen this password more than the configured limit.

    Separate from :func:`check` because it is network I/O and cannot live in a
    pydantic validator: those run synchronously inside request parsing, where a
    blocking HTTP call would stall the event loop for every other request in
    flight. Runs in a threadpool for the same reason.
    """
    from fastapi import HTTPException, status
    from starlette.concurrency import run_in_threadpool

    from config import settings

    if not settings.password_hibp_check_enabled:
        return

    count = await run_in_threadpool(pwned_count, password)
    if count >= settings.password_hibp_max_appearances:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "This password has appeared in a known data breach. "
                "Choose one you have not used anywhere else."
            ),
        )
