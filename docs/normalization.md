names -> NFC unicode, strip spaces, title-case
citizenship -> choose ISO 3166-1 alpha-2 codes (e.g., UK→GB, USA→US) or keep canonical names; be consistent
map status/license_class to fixed enums
convert dates to days since epoch integers (this makes range proofs simpler)