from __future__ import annotations

from .base import AbstractAnonymizationService
from .age_anonymization_service import AgeAnonymizationService
from .email_address_anonymization_service import EmailAddressAnonymizationService
from .credit_card_anonymization_service import CreditCardAnonymizationService
from .ssn_anonymization_service import SSNAnonymizationService
from .phone_number_anonymization_service import PhoneNumberAnonymizationService
from .ip_address_anonymization_service import IPAddressAnonymizationService
from .url_anonymization_service import URLAnonymizationService
from .zip_code_anonymization_service import ZipCodeAnonymizationService
from .vin_anonymization_service import VINAnonymizationService
from .bitcoin_address_anonymization_service import BitcoinAddressAnonymizationService
from .bank_routing_number_anonymization_service import BankRoutingNumberAnonymizationService
from .date_anonymization_service import DateAnonymizationService
from .mac_address_anonymization_service import MACAddressAnonymizationService
from .currency_anonymization_service import CurrencyAnonymizationService
from .street_address_anonymization_service import StreetAddressAnonymizationService
from .tracking_number_anonymization_service import TrackingNumberAnonymizationService
from .drivers_license_anonymization_service import DriversLicenseAnonymizationService
from .iban_code_anonymization_service import IBANCodeAnonymizationService
from .passport_number_anonymization_service import PassportNumberAnonymizationService

# Maps filter_type strings to their anonymization service instances.
_REGISTRY: dict[str, AbstractAnonymizationService] = {
    "age": AgeAnonymizationService(),
    "email-address": EmailAddressAnonymizationService(),
    "credit-card": CreditCardAnonymizationService(),
    "ssn": SSNAnonymizationService(),
    "phone-number": PhoneNumberAnonymizationService(),
    "ip-address": IPAddressAnonymizationService(),
    "url": URLAnonymizationService(),
    "zip-code": ZipCodeAnonymizationService(),
    "vin": VINAnonymizationService(),
    "bitcoin-address": BitcoinAddressAnonymizationService(),
    "bank-routing-number": BankRoutingNumberAnonymizationService(),
    "date": DateAnonymizationService(),
    "mac-address": MACAddressAnonymizationService(),
    "currency": CurrencyAnonymizationService(),
    "street-address": StreetAddressAnonymizationService(),
    "tracking-number": TrackingNumberAnonymizationService(),
    "drivers-license": DriversLicenseAnonymizationService(),
    "iban-code": IBANCodeAnonymizationService(),
    "passport-number": PassportNumberAnonymizationService(),
}


def get_anonymization_service(filter_type: str) -> AbstractAnonymizationService | None:
    """Return the anonymization service for the given filter type, or None if not found."""
    return _REGISTRY.get(filter_type)


__all__ = [
    "AbstractAnonymizationService",
    "AgeAnonymizationService",
    "EmailAddressAnonymizationService",
    "CreditCardAnonymizationService",
    "SSNAnonymizationService",
    "PhoneNumberAnonymizationService",
    "IPAddressAnonymizationService",
    "URLAnonymizationService",
    "ZipCodeAnonymizationService",
    "VINAnonymizationService",
    "BitcoinAddressAnonymizationService",
    "BankRoutingNumberAnonymizationService",
    "DateAnonymizationService",
    "MACAddressAnonymizationService",
    "CurrencyAnonymizationService",
    "StreetAddressAnonymizationService",
    "TrackingNumberAnonymizationService",
    "DriversLicenseAnonymizationService",
    "IBANCodeAnonymizationService",
    "PassportNumberAnonymizationService",
    "get_anonymization_service",
]
