from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .filter_strategy import FilterStrategy


def _default_strategies():
    return [FilterStrategy()]


@dataclass
class AgeFilterConfig:
    enabled: bool = True
    age_filter_strategies: List[FilterStrategy] = field(default_factory=_default_strategies)
    ignored: List[str] = field(default_factory=list)


@dataclass
class EmailAddressFilterConfig:
    enabled: bool = True
    email_address_filter_strategies: List[FilterStrategy] = field(default_factory=_default_strategies)
    ignored: List[str] = field(default_factory=list)


@dataclass
class CreditCardFilterConfig:
    enabled: bool = True
    credit_card_filter_strategies: List[FilterStrategy] = field(default_factory=_default_strategies)
    ignored: List[str] = field(default_factory=list)


@dataclass
class SSNFilterConfig:
    enabled: bool = True
    ssn_filter_strategies: List[FilterStrategy] = field(default_factory=_default_strategies)
    ignored: List[str] = field(default_factory=list)


@dataclass
class PhoneNumberFilterConfig:
    enabled: bool = True
    phone_number_filter_strategies: List[FilterStrategy] = field(default_factory=_default_strategies)
    ignored: List[str] = field(default_factory=list)


@dataclass
class IPAddressFilterConfig:
    enabled: bool = True
    ip_address_filter_strategies: List[FilterStrategy] = field(default_factory=_default_strategies)
    ignored: List[str] = field(default_factory=list)


@dataclass
class URLFilterConfig:
    enabled: bool = True
    url_filter_strategies: List[FilterStrategy] = field(default_factory=_default_strategies)
    ignored: List[str] = field(default_factory=list)


@dataclass
class ZipCodeFilterConfig:
    enabled: bool = True
    zip_code_filter_strategies: List[FilterStrategy] = field(default_factory=_default_strategies)
    ignored: List[str] = field(default_factory=list)


@dataclass
class VINFilterConfig:
    enabled: bool = True
    vin_filter_strategies: List[FilterStrategy] = field(default_factory=_default_strategies)
    ignored: List[str] = field(default_factory=list)


@dataclass
class BitcoinAddressFilterConfig:
    enabled: bool = True
    bitcoin_address_filter_strategies: List[FilterStrategy] = field(default_factory=_default_strategies)
    ignored: List[str] = field(default_factory=list)


@dataclass
class BankRoutingNumberFilterConfig:
    enabled: bool = True
    bank_routing_number_filter_strategies: List[FilterStrategy] = field(default_factory=_default_strategies)
    ignored: List[str] = field(default_factory=list)


@dataclass
class DateFilterConfig:
    enabled: bool = True
    date_filter_strategies: List[FilterStrategy] = field(default_factory=_default_strategies)
    ignored: List[str] = field(default_factory=list)


@dataclass
class MACAddressFilterConfig:
    enabled: bool = True
    mac_address_filter_strategies: List[FilterStrategy] = field(default_factory=_default_strategies)
    ignored: List[str] = field(default_factory=list)


@dataclass
class CurrencyFilterConfig:
    enabled: bool = True
    currency_filter_strategies: List[FilterStrategy] = field(default_factory=_default_strategies)
    ignored: List[str] = field(default_factory=list)


@dataclass
class StreetAddressFilterConfig:
    enabled: bool = True
    street_address_filter_strategies: List[FilterStrategy] = field(default_factory=_default_strategies)
    ignored: List[str] = field(default_factory=list)


@dataclass
class TrackingNumberFilterConfig:
    enabled: bool = True
    tracking_number_filter_strategies: List[FilterStrategy] = field(default_factory=_default_strategies)
    ignored: List[str] = field(default_factory=list)


@dataclass
class DriversLicenseFilterConfig:
    enabled: bool = True
    drivers_license_filter_strategies: List[FilterStrategy] = field(default_factory=_default_strategies)
    ignored: List[str] = field(default_factory=list)


@dataclass
class IBANCodeFilterConfig:
    enabled: bool = True
    iban_code_filter_strategies: List[FilterStrategy] = field(default_factory=_default_strategies)
    ignored: List[str] = field(default_factory=list)


@dataclass
class PassportNumberFilterConfig:
    enabled: bool = True
    passport_number_filter_strategies: List[FilterStrategy] = field(default_factory=_default_strategies)
    ignored: List[str] = field(default_factory=list)


def _strategies_from_dict(data: dict, key: str) -> List[FilterStrategy]:
    raw = data.get(key, [])
    if raw:
        return [FilterStrategy.from_dict(s) for s in raw]
    return [FilterStrategy()]


class Identifiers:
    def __init__(self):
        self.age: Optional[AgeFilterConfig] = None
        self.email_address: Optional[EmailAddressFilterConfig] = None
        self.credit_card: Optional[CreditCardFilterConfig] = None
        self.ssn: Optional[SSNFilterConfig] = None
        self.phone_number: Optional[PhoneNumberFilterConfig] = None
        self.ip_address: Optional[IPAddressFilterConfig] = None
        self.url: Optional[URLFilterConfig] = None
        self.zip_code: Optional[ZipCodeFilterConfig] = None
        self.vin: Optional[VINFilterConfig] = None
        self.bitcoin_address: Optional[BitcoinAddressFilterConfig] = None
        self.bank_routing_number: Optional[BankRoutingNumberFilterConfig] = None
        self.date: Optional[DateFilterConfig] = None
        self.mac_address: Optional[MACAddressFilterConfig] = None
        self.currency: Optional[CurrencyFilterConfig] = None
        self.street_address: Optional[StreetAddressFilterConfig] = None
        self.tracking_number: Optional[TrackingNumberFilterConfig] = None
        self.drivers_license: Optional[DriversLicenseFilterConfig] = None
        self.iban_code: Optional[IBANCodeFilterConfig] = None
        self.passport_number: Optional[PassportNumberFilterConfig] = None

    @classmethod
    def from_dict(cls, data: dict) -> "Identifiers":
        obj = cls()
        if "age" in data:
            d = data["age"]
            obj.age = AgeFilterConfig(
                enabled=d.get("enabled", True),
                age_filter_strategies=_strategies_from_dict(d, "ageFilterStrategies"),
                ignored=d.get("ignored", []),
            )
        if "emailAddress" in data:
            d = data["emailAddress"]
            obj.email_address = EmailAddressFilterConfig(
                enabled=d.get("enabled", True),
                email_address_filter_strategies=_strategies_from_dict(d, "emailAddressFilterStrategies"),
                ignored=d.get("ignored", []),
            )
        if "creditCard" in data:
            d = data["creditCard"]
            obj.credit_card = CreditCardFilterConfig(
                enabled=d.get("enabled", True),
                credit_card_filter_strategies=_strategies_from_dict(d, "creditCardFilterStrategies"),
                ignored=d.get("ignored", []),
            )
        if "ssn" in data:
            d = data["ssn"]
            obj.ssn = SSNFilterConfig(
                enabled=d.get("enabled", True),
                ssn_filter_strategies=_strategies_from_dict(d, "ssnFilterStrategies"),
                ignored=d.get("ignored", []),
            )
        if "phoneNumber" in data:
            d = data["phoneNumber"]
            obj.phone_number = PhoneNumberFilterConfig(
                enabled=d.get("enabled", True),
                phone_number_filter_strategies=_strategies_from_dict(d, "phoneNumberFilterStrategies"),
                ignored=d.get("ignored", []),
            )
        if "ipAddress" in data:
            d = data["ipAddress"]
            obj.ip_address = IPAddressFilterConfig(
                enabled=d.get("enabled", True),
                ip_address_filter_strategies=_strategies_from_dict(d, "ipAddressFilterStrategies"),
                ignored=d.get("ignored", []),
            )
        if "url" in data:
            d = data["url"]
            obj.url = URLFilterConfig(
                enabled=d.get("enabled", True),
                url_filter_strategies=_strategies_from_dict(d, "urlFilterStrategies"),
                ignored=d.get("ignored", []),
            )
        if "zipCode" in data:
            d = data["zipCode"]
            obj.zip_code = ZipCodeFilterConfig(
                enabled=d.get("enabled", True),
                zip_code_filter_strategies=_strategies_from_dict(d, "zipCodeFilterStrategies"),
                ignored=d.get("ignored", []),
            )
        if "vin" in data:
            d = data["vin"]
            obj.vin = VINFilterConfig(
                enabled=d.get("enabled", True),
                vin_filter_strategies=_strategies_from_dict(d, "vinFilterStrategies"),
                ignored=d.get("ignored", []),
            )
        if "bitcoinAddress" in data:
            d = data["bitcoinAddress"]
            obj.bitcoin_address = BitcoinAddressFilterConfig(
                enabled=d.get("enabled", True),
                bitcoin_address_filter_strategies=_strategies_from_dict(d, "bitcoinAddressFilterStrategies"),
                ignored=d.get("ignored", []),
            )
        if "bankRoutingNumber" in data:
            d = data["bankRoutingNumber"]
            obj.bank_routing_number = BankRoutingNumberFilterConfig(
                enabled=d.get("enabled", True),
                bank_routing_number_filter_strategies=_strategies_from_dict(d, "bankRoutingNumberFilterStrategies"),
                ignored=d.get("ignored", []),
            )
        if "date" in data:
            d = data["date"]
            obj.date = DateFilterConfig(
                enabled=d.get("enabled", True),
                date_filter_strategies=_strategies_from_dict(d, "dateFilterStrategies"),
                ignored=d.get("ignored", []),
            )
        if "macAddress" in data:
            d = data["macAddress"]
            obj.mac_address = MACAddressFilterConfig(
                enabled=d.get("enabled", True),
                mac_address_filter_strategies=_strategies_from_dict(d, "macAddressFilterStrategies"),
                ignored=d.get("ignored", []),
            )
        if "currency" in data:
            d = data["currency"]
            obj.currency = CurrencyFilterConfig(
                enabled=d.get("enabled", True),
                currency_filter_strategies=_strategies_from_dict(d, "currencyFilterStrategies"),
                ignored=d.get("ignored", []),
            )
        if "streetAddress" in data:
            d = data["streetAddress"]
            obj.street_address = StreetAddressFilterConfig(
                enabled=d.get("enabled", True),
                street_address_filter_strategies=_strategies_from_dict(d, "streetAddressFilterStrategies"),
                ignored=d.get("ignored", []),
            )
        if "trackingNumber" in data:
            d = data["trackingNumber"]
            obj.tracking_number = TrackingNumberFilterConfig(
                enabled=d.get("enabled", True),
                tracking_number_filter_strategies=_strategies_from_dict(d, "trackingNumberFilterStrategies"),
                ignored=d.get("ignored", []),
            )
        if "driversLicense" in data:
            d = data["driversLicense"]
            obj.drivers_license = DriversLicenseFilterConfig(
                enabled=d.get("enabled", True),
                drivers_license_filter_strategies=_strategies_from_dict(d, "driversLicenseFilterStrategies"),
                ignored=d.get("ignored", []),
            )
        if "ibanCode" in data:
            d = data["ibanCode"]
            obj.iban_code = IBANCodeFilterConfig(
                enabled=d.get("enabled", True),
                iban_code_filter_strategies=_strategies_from_dict(d, "ibanCodeFilterStrategies"),
                ignored=d.get("ignored", []),
            )
        if "passportNumber" in data:
            d = data["passportNumber"]
            obj.passport_number = PassportNumberFilterConfig(
                enabled=d.get("enabled", True),
                passport_number_filter_strategies=_strategies_from_dict(d, "passportNumberFilterStrategies"),
                ignored=d.get("ignored", []),
            )
        return obj

    def to_dict(self) -> dict:
        d: dict = {}
        if self.age is not None:
            d["age"] = {
                "enabled": self.age.enabled,
                "ageFilterStrategies": [s.to_dict() for s in self.age.age_filter_strategies],
                "ignored": self.age.ignored,
            }
        if self.email_address is not None:
            d["emailAddress"] = {
                "enabled": self.email_address.enabled,
                "emailAddressFilterStrategies": [s.to_dict() for s in self.email_address.email_address_filter_strategies],
                "ignored": self.email_address.ignored,
            }
        if self.credit_card is not None:
            d["creditCard"] = {
                "enabled": self.credit_card.enabled,
                "creditCardFilterStrategies": [s.to_dict() for s in self.credit_card.credit_card_filter_strategies],
                "ignored": self.credit_card.ignored,
            }
        if self.ssn is not None:
            d["ssn"] = {
                "enabled": self.ssn.enabled,
                "ssnFilterStrategies": [s.to_dict() for s in self.ssn.ssn_filter_strategies],
                "ignored": self.ssn.ignored,
            }
        if self.phone_number is not None:
            d["phoneNumber"] = {
                "enabled": self.phone_number.enabled,
                "phoneNumberFilterStrategies": [s.to_dict() for s in self.phone_number.phone_number_filter_strategies],
                "ignored": self.phone_number.ignored,
            }
        if self.ip_address is not None:
            d["ipAddress"] = {
                "enabled": self.ip_address.enabled,
                "ipAddressFilterStrategies": [s.to_dict() for s in self.ip_address.ip_address_filter_strategies],
                "ignored": self.ip_address.ignored,
            }
        if self.url is not None:
            d["url"] = {
                "enabled": self.url.enabled,
                "urlFilterStrategies": [s.to_dict() for s in self.url.url_filter_strategies],
                "ignored": self.url.ignored,
            }
        if self.zip_code is not None:
            d["zipCode"] = {
                "enabled": self.zip_code.enabled,
                "zipCodeFilterStrategies": [s.to_dict() for s in self.zip_code.zip_code_filter_strategies],
                "ignored": self.zip_code.ignored,
            }
        if self.vin is not None:
            d["vin"] = {
                "enabled": self.vin.enabled,
                "vinFilterStrategies": [s.to_dict() for s in self.vin.vin_filter_strategies],
                "ignored": self.vin.ignored,
            }
        if self.bitcoin_address is not None:
            d["bitcoinAddress"] = {
                "enabled": self.bitcoin_address.enabled,
                "bitcoinAddressFilterStrategies": [s.to_dict() for s in self.bitcoin_address.bitcoin_address_filter_strategies],
                "ignored": self.bitcoin_address.ignored,
            }
        if self.bank_routing_number is not None:
            d["bankRoutingNumber"] = {
                "enabled": self.bank_routing_number.enabled,
                "bankRoutingNumberFilterStrategies": [s.to_dict() for s in self.bank_routing_number.bank_routing_number_filter_strategies],
                "ignored": self.bank_routing_number.ignored,
            }
        if self.date is not None:
            d["date"] = {
                "enabled": self.date.enabled,
                "dateFilterStrategies": [s.to_dict() for s in self.date.date_filter_strategies],
                "ignored": self.date.ignored,
            }
        if self.mac_address is not None:
            d["macAddress"] = {
                "enabled": self.mac_address.enabled,
                "macAddressFilterStrategies": [s.to_dict() for s in self.mac_address.mac_address_filter_strategies],
                "ignored": self.mac_address.ignored,
            }
        if self.currency is not None:
            d["currency"] = {
                "enabled": self.currency.enabled,
                "currencyFilterStrategies": [s.to_dict() for s in self.currency.currency_filter_strategies],
                "ignored": self.currency.ignored,
            }
        if self.street_address is not None:
            d["streetAddress"] = {
                "enabled": self.street_address.enabled,
                "streetAddressFilterStrategies": [s.to_dict() for s in self.street_address.street_address_filter_strategies],
                "ignored": self.street_address.ignored,
            }
        if self.tracking_number is not None:
            d["trackingNumber"] = {
                "enabled": self.tracking_number.enabled,
                "trackingNumberFilterStrategies": [s.to_dict() for s in self.tracking_number.tracking_number_filter_strategies],
                "ignored": self.tracking_number.ignored,
            }
        if self.drivers_license is not None:
            d["driversLicense"] = {
                "enabled": self.drivers_license.enabled,
                "driversLicenseFilterStrategies": [s.to_dict() for s in self.drivers_license.drivers_license_filter_strategies],
                "ignored": self.drivers_license.ignored,
            }
        if self.iban_code is not None:
            d["ibanCode"] = {
                "enabled": self.iban_code.enabled,
                "ibanCodeFilterStrategies": [s.to_dict() for s in self.iban_code.iban_code_filter_strategies],
                "ignored": self.iban_code.ignored,
            }
        if self.passport_number is not None:
            d["passportNumber"] = {
                "enabled": self.passport_number.enabled,
                "passportNumberFilterStrategies": [s.to_dict() for s in self.passport_number.passport_number_filter_strategies],
                "ignored": self.passport_number.ignored,
            }
        return d
