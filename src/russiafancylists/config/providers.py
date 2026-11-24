import json
from dataclasses import dataclass, field
from pathlib import Path

from russiafancylists.config.paths import TEMP_FOLDER


@dataclass(frozen=True)
class SmartDNSProvider:
    key: str
    name: str
    doh_endpoints: dict[str, str] = field(default_factory=dict)
    dns_endpoints: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    download_sources: list[dict[str, str]] = field(default_factory=list)
    default_ips: list[str] = field(default_factory=list)
    primary_fallback: bool = False
    fallback_to_disk: bool = False

    @property
    def hosts_filename(self) -> str:
        return f"{self.key}.hosts"

    @property
    def no_crutch_hosts_filename(self) -> str:
        return f"{self.key}-no-crutch.hosts"

    @property
    def adguard_filename(self) -> str:
        return f"{self.key}.adguard.txt"

    @property
    def no_crutch_adguard_filename(self) -> str:
        return f"{self.key}-no-crutch.adguard.txt"

    @property
    def all_filenames(self) -> list[str]:
        return [
            self.hosts_filename,
            self.no_crutch_hosts_filename,
            self.adguard_filename,
            self.no_crutch_adguard_filename,
        ]

    @property
    def download_filenames(self) -> list[str]:
        return [
            s["temp_filename"] for s in self.download_sources if "temp_filename" in s
        ]


def _load_providers() -> list[SmartDNSProvider]:
    config_file = Path(__file__).parent / "providers.json"
    with open(config_file, encoding="utf-8") as f:
        data = json.load(f)
    return [SmartDNSProvider(**item) for item in data]


# Loaded provider instances from central providers.json
PROVIDERS: list[SmartDNSProvider] = _load_providers()
PROVIDERS_BY_KEY: dict[str, SmartDNSProvider] = {p.key: p for p in PROVIDERS}
CANONICAL_PROVIDER_KEYS: list[str] = [p.key for p in PROVIDERS]
PROVIDER_DISPLAY_NAMES: dict[str, str] = {p.key: p.name for p in PROVIDERS}
PRIMARY_FALLBACK_PROVIDERS: list[str] = [p.key for p in PROVIDERS if p.primary_fallback]

PROVIDER_NAME_TO_KEY: dict[str, str] = {}
for p in PROVIDERS:
    PROVIDER_NAME_TO_KEY[p.name] = p.key
    PROVIDER_NAME_TO_KEY[p.key] = p.key
    for alias in p.aliases:
        PROVIDER_NAME_TO_KEY[alias] = p.key
# Common aliases / short names
PROVIDER_NAME_TO_KEY["Malw"] = "malw"

# Smart DNS / DoH endpoints for harvesting SNI proxy IP addresses
SMART_DNS_DOH_SERVERS: dict[str, str] = {}
for p in PROVIDERS:
    SMART_DNS_DOH_SERVERS.update(p.doh_endpoints)

# Map DoH endpoint names and aliases to canonical provider keys
DOH_TO_CANONICAL: dict[str, str] = {}
for p in PROVIDERS:
    DOH_TO_CANONICAL[p.key] = p.key
    for endpoint_name in p.doh_endpoints:
        DOH_TO_CANONICAL[endpoint_name] = p.key
    for alias in p.aliases:
        DOH_TO_CANONICAL[alias] = p.key

# Geoblock and crutch download sources
DOWNLOADS: dict[str, tuple[str, Path, str]] = {
    # External Geoblock Sources
    "itdoginfo_hosts": (
        "https://raw.githubusercontent.com/itdoginfo/allow-domains/refs/heads/main/Categories/geoblock.lst",
        TEMP_FOLDER / "hosts" / "itdoginfo-geoblock.lst",
        "ItDogInfo's geoblock domains",
    ),
    "dartraiden_hosts": (
        "https://raw.githubusercontent.com/dartraiden/no-russia-hosts/refs/heads/master/hosts.txt",
        TEMP_FOLDER / "hosts" / "dartraiden-geoblock.lst",
        "Dartraiden's no-russia hosts",
    ),
    "zapret_manager_sh": (
        "https://raw.githubusercontent.com/StressOzz/Zapret-Manager/refs/heads/main/Zapret-Manager.sh",
        TEMP_FOLDER / "zapret-manager.sh",
        "Zapret-Manager shell script",
    ),
    "malw_hosts": (
        "https://raw.githubusercontent.com/ImMALWARE/dns.malw.link/refs/heads/master/hosts",
        TEMP_FOLDER / "hosts" / "malw-hosts.lst",
        "ImMALWARE's hosts",
    ),
    "geohide_eu_hosts": (
        "https://geohide.ru/eu/hosts",
        TEMP_FOLDER / "hosts" / "geohide-eu-hosts.lst",
        "GeoHide's EU hosts",
    ),
    "geohide_us_hosts": (
        "https://geohide.ru/us/hosts",
        TEMP_FOLDER / "hosts" / "geohide-us-hosts.lst",
        "GeoHide's US hosts",
    ),
    "astracat_hosts": (
        "https://raw.githubusercontent.com/ASTRACAT2022/host-DNS/main/base_hosts.txt",
        TEMP_FOLDER / "hosts" / "astracat-hosts.lst",
        "AstraCat's hosts",
    ),
}

# Dynamically merge all provider download sources into DOWNLOADS
for p in PROVIDERS:
    for src in p.download_sources:
        DOWNLOADS[src["id"]] = (
            src["url"],
            TEMP_FOLDER / "hosts" / src["temp_filename"],
            src["description"],
        )

# Canonical geoblocked domains used to probe DoH resolvers for proxy IPs
DOH_PROBE_DOMAINS = [
    # OpenAI / ChatGPT
    "chatgpt.com",
    "openai.com",
    "auth.openai.com",
    "api.openai.com",
    # Anthropic / Claude
    "claude.ai",
    "anthropic.com",
    "api.anthropic.com",
    # Google Gemini & AI Studio
    "gemini.google.com",
    "aistudio.google.com",
    "notebooklm.google.com",
    "generativelanguage.googleapis.com",
    # Microsoft Copilot
    "copilot.microsoft.com",
    "sydney.bing.com",
    # xAI / Grok
    "grok.com",
    "x.ai",
    "console.x.ai",
    # AI Search & Generation
    "genspark.ai",
    "manus.im",
    "perplexity.ai",
    # Gaming & Consoles
    "xsts.auth.xboxlive.com",
    "xboxlive.com",
    "playstation.net",
    "ea.com",
    "blizzard.com",
    "battle.net",
    # Media & Fitness
    "deezer.com",
    "tidal.com",
    "spotify.com",
    "soundcloud.com",
    "strava.com",
    "rutracker.org",
    # Work, Design & Tech
    "canva.com",
    "notion.so",
    "intel.com",
    "dell.com",
    "jetbrains.com",
    # Additional AI Geoblocks
    "cursor.com",
    "sora.com",
]
