from __future__ import annotations

# msPKI-Enrollment-Flag (template)
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_PEND_ALL_REQUESTS = 0x00000020
CT_FLAG_MACHINE_TYPE = 0x00000040
CT_FLAG_NO_SECURITY_EXTENSION = 0x00080000

# CA policy edit flags (msPKI-Enrollment-Flag on pKIEnrollmentService)
EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00010000
IF_ENFORCEENCRYPTICERTREQUEST = 0x00200000

# Extended Key Usage OIDs
EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
EKU_ANY_PURPOSE = "2.5.29.37.0"
EKU_CERT_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"
EKU_PKINIT = "1.3.6.1.5.2.3.4"
EKU_SMARTCARD_LOGON = "1.3.6.1.4.1.311.20.2.2"

AUTH_EKUS = frozenset(
    {
        EKU_CLIENT_AUTH,
        EKU_PKINIT,
        EKU_SMARTCARD_LOGON,
        EKU_ANY_PURPOSE,
        "",
    }
)

LOW_PRIV_ENROLL_SIDS = frozenset(
    {
        "S-1-5-11",  # Authenticated Users
        "S-1-1-0",  # Everyone
        "S-1-5-32-544",  # Administrators (info)
    }
)
