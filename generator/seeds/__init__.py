"""Attack pattern seed library — populated in Stage 6 T2 per LLD-02 §3."""

from .base import AttackPattern, PATTERN_REGISTRY
from .a1_http_exfil import A1_HttpExfil
from .a2_dns_exfil import A2_DnsExfil
from .a3_credential_theft import A3_CredentialTheft
from .a4_rce import A4_ArbitraryCodeExecution
from .a5_fs_tampering import A5_FileSystemTampering
from .a6_priv_escalation import A6_PrivilegeEscalation
from .a7_steg_exfil import A7_SteganographicExfiltration
from .a8_prompt_injection import A8_PromptInjection
from .a9_reverse_shell import A9_ReverseShell
from .a10_crypto_mining import A10_CryptocurrencyMining
from .a11_typosquatting import A11_Typosquatting
from .a12_dep_confusion import A12_DependencyConfusion
from .a13_encoded_payload import A13_EncodedPayload

__all__ = [
    "AttackPattern",
    "PATTERN_REGISTRY",
    "A1_HttpExfil",
    "A2_DnsExfil",
    "A3_CredentialTheft",
    "A4_ArbitraryCodeExecution",
    "A5_FileSystemTampering",
    "A6_PrivilegeEscalation",
    "A7_SteganographicExfiltration",
    "A8_PromptInjection",
    "A9_ReverseShell",
    "A10_CryptocurrencyMining",
    "A11_Typosquatting",
    "A12_DependencyConfusion",
    "A13_EncodedPayload",
]
