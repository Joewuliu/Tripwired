import json
import re
from pathlib import Path

import pytest

from brands import BRANDS, check_brand
from enrich import registered_domain
from platforms import FREE_HOSTING_PLATFORMS, SHARED_HOSTS, is_free_host

BY_NAME = {b["brand"]: b for b in BRANDS}
MUST_HAVE = [
    "Chase", "Bank of America", "Wells Fargo", "Capital One", "USPS", "UPS", "FedEx", "DHL", "E-ZPass",
    "NC DMV", "IRS", "Apple", "Microsoft", "Google", "Amazon", "Netflix", "PayPal", "Venmo", "Zelle",
    "Coinbase", "Facebook", "Instagram", "WhatsApp", "Steam", "Roblox", "Ledger", "Trezor",
]


def test_the_list_is_big_enough_and_every_brand_is_unique():
    assert len(BRANDS) >= 60
    assert len(BY_NAME) == len(BRANDS)
    assert set(MUST_HAVE) <= set(BY_NAME)


def test_entries_are_well_formed():
    for brand in BRANDS:
        assert set(brand) <= {"brand", "keywords", "address_keywords", "official_domains", "verify"}, brand["brand"]
        assert brand["keywords"] and all(k == k.lower() and k.strip() for k in brand["keywords"]), brand["brand"]
        assert all(k == k.lower() and k.strip() for k in brand.get("address_keywords", [])), brand["brand"]
        assert brand["official_domains"], brand["brand"]
        assert brand.get("verify", True) is True


def test_every_official_domain_is_a_bare_registered_domain():
    for brand in BRANDS:
        for domain in brand["official_domains"]:
            assert re.fullmatch(r"[a-z0-9.-]+\.[a-z]+", domain), domain
            assert registered_domain(domain) == domain, f"{domain} is not a registered domain, so it would never match"


def test_no_official_domain_belongs_to_two_brands():
    owners: dict[str, str] = {}
    for brand in BRANDS:
        for domain in brand["official_domains"]:
            assert domain not in owners, f"{domain}: {owners[domain]} and {brand['brand']}"
            owners[domain] = brand["brand"]


def test_no_official_domain_is_a_place_where_anyone_can_publish():
    """A wrong entry here would whitelist scams, so user-content and free-hosting names must never be official."""
    for brand in BRANDS:
        for domain in brand["official_domains"]:
            assert not is_free_host(domain), f"{brand['brand']}: {domain} lets anyone publish"
            assert domain not in FREE_HOSTING_PLATFORMS and domain not in SHARED_HOSTS


def test_the_less_certain_entries_are_marked_for_review():
    flagged = {b["brand"] for b in BRANDS if b.get("verify")}
    assert {"E-ZPass", "NC DMV", "Spectrum", "DHL", "Cash App", "Zelle", "SunPass", "TxTag"} <= flagged


def test_the_file_is_valid_json_with_one_entry_per_line():
    text = (Path(__file__).parent / "data" / "brands.json").read_text(encoding="utf-8")
    assert json.loads(text) == BRANDS
    assert text.count('{"brand"') == len(BRANDS)


@pytest.mark.parametrize("brand", BRANDS, ids=lambda b: b["brand"])
def test_each_brands_official_domains_report_only_that_brand(brand):
    for domain in brand["official_domains"]:
        found = {(f["type"], f["brand"]) for f in check_brand(f"https://www.{domain}/")}
        assert found == {("official", brand["brand"])}, f"{domain}: {found}"


@pytest.mark.parametrize("brand", BRANDS, ids=lambda b: b["brand"])
def test_a_scam_domain_built_from_each_brands_name_is_caught(brand):
    name = brand["keywords"][0].replace(" ", "-").replace("&", "")
    found = {(f["type"], f["brand"]) for f in check_brand(f"https://{name}-account-verify.top/login")}
    assert ("impersonation", brand["brand"]) in found
