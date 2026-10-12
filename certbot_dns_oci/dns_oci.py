"""DNS Authenticator for Oracle Cloud Infrastructure."""

import configparser
import logging
from typing import Any, Callable

import oci
from circuitbreaker import CircuitBreakerError
from certbot import configuration, errors
from certbot.compat import os
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


class Authenticator(dns_common.DNSAuthenticator):
    """Fulfil DNS-01 challenges using OCI public DNS."""

    description = "Obtain certificates using a DNS TXT record (if you are using OCI for DNS)."
    ttl = 60

    def __init__(self, config: configuration.NamespaceConfig, name: str) -> None:
        super().__init__(config, name)
        self._client: _OCIDNSClient | None = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None], **kwargs: Any) -> None:
        super().add_parser_arguments(add, default_propagation_seconds=15)
        add("config", help="OCI SDK configuration file (default: OCI SDK search paths).")
        add("profile", help="OCI configuration profile (default: DEFAULT).")

    def more_info(self) -> str:
        return "This plugin creates and removes DNS-01 TXT records using the OCI DNS API."

    def _setup_credentials(self) -> None:
        self._get_ocidns_client()

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_ocidns_client().add_txt_record(
            domain, validation_name, validation, self.ttl
        )

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_ocidns_client().del_txt_record(domain, validation_name, validation)

    def _config_file_path(self) -> str:
        """Resolve OCI's documented default search order without private SDK APIs."""
        path = self.conf("config")
        if not path:
            path = oci.config.DEFAULT_LOCATION
            if not os.path.isfile(os.path.expanduser(path)):
                fallback = oci.config.FALLBACK_DEFAULT_LOCATION
                if os.environ.get("OCI_CONFIG_FILE"):
                    path = os.environ["OCI_CONFIG_FILE"]
                elif os.path.isfile(os.path.expanduser(fallback)):
                    path = fallback
        return os.path.abspath(os.path.expanduser(path))

    def _get_ocidns_client(self) -> "_OCIDNSClient":
        if self._client is None:
            config_path = self._config_file_path()
            profile = self.conf("profile") or oci.config.DEFAULT_PROFILE
            try:
                dns_common.validate_file_permissions(config_path)
                config = oci.config.from_file(file_location=config_path, profile_name=profile)
                oci.config.validate_config(config)
                self._client = _OCIDNSClient(config)
            except (oci.exceptions.ClientError, OSError, ValueError, configparser.Error) as err:
                raise errors.PluginError(
                    f"Unable to load OCI credentials from {config_path!r} "
                    f"(profile {profile!r}; {type(err).__name__}). "
                    "Check the configuration, API signing key, and region."
                ) from err

            # Certbot persists plugin options for renewal. Store the resolved path
            # so a different working directory or environment cannot change it.
            setattr(self.config, self.dest("config"), config_path)
            setattr(self.config, self.dest("profile"), profile)
        return self._client


class _ZoneNotFound(errors.PluginError):
    """No accessible public zone was found for the challenge."""


class _OCIDNSClient:
    """Use value-specific PATCH operations without replacing other TXT records."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.dns_client = oci.dns.DnsClient(config)
        self._zones: dict[str, tuple[str, str]] = {}

    @staticmethod
    def _api_error(action: str, err: oci.exceptions.ServiceError) -> errors.PluginError:
        return errors.PluginError(
            f"OCI DNS error while {action}: HTTP {err.status} ({err.code}). "
            "Check the OCI credentials, region, and DNS permissions."
        )

    def add_txt_record(
        self, domain: str, record_name: str, record_content: str, record_ttl: int
    ) -> None:
        """Add only the challenge's TXT value to the public zone."""
        zone_id, _ = self._find_managed_zone(domain, record_name)
        record = oci.dns.models.RecordOperation(
            operation="ADD", domain=record_name, rtype="TXT",
            rdata=record_content, ttl=record_ttl,
        )
        try:
            self.dns_client.patch_domain_records(
                zone_id, record_name,
                oci.dns.models.PatchDomainRecordsDetails(items=[record]),
                scope="GLOBAL",
            )
        except oci.exceptions.ServiceError as err:
            raise self._api_error(f"adding TXT record {record_name}", err) from err
        except (
            oci.exceptions.RequestException, oci.exceptions.ConnectTimeout, CircuitBreakerError
        ) as err:
            raise errors.PluginError(f"Unable to reach OCI DNS to add {record_name}.") from err
        logger.debug("Added TXT record %s in zone %s", record_name, zone_id)

    def del_txt_record(self, domain: str, record_name: str, record_content: str) -> None:
        """Remove the challenge value, leaving other values and record types intact."""
        try:
            zone_id, _ = self._find_managed_zone(domain, record_name)
        except _ZoneNotFound:
            logger.warning("Cannot find an accessible public zone to clean up %s", record_name)
            return
        record = oci.dns.models.RecordOperation(
            operation="REMOVE", domain=record_name, rtype="TXT", rdata=record_content,
        )
        try:
            self.dns_client.patch_domain_records(
                zone_id, record_name,
                oci.dns.models.PatchDomainRecordsDetails(items=[record]),
                scope="GLOBAL",
            )
        except oci.exceptions.ServiceError as err:
            if err.status == 404:
                # OCI also uses 404 for inaccessible resources; keep that visible.
                logger.warning(
                    "Record or zone missing or inaccessible during cleanup of %s", record_name
                )
                return
            raise self._api_error(f"removing TXT record {record_name}", err) from err
        except (
            oci.exceptions.RequestException, oci.exceptions.ConnectTimeout, CircuitBreakerError
        ) as err:
            raise errors.PluginError(f"Unable to reach OCI DNS to remove {record_name}.") from err
        logger.debug("Removed TXT record %s in zone %s", record_name, zone_id)

    def _find_managed_zone(self, domain: str, record_name: str) -> tuple[str, str]:
        """Find the most specific accessible public zone for the record."""
        record_name = record_name.rstrip(".").lower()
        if record_name in self._zones:
            return self._zones[record_name]

        for zone_name in dns_common.base_domain_name_guesses(record_name):
            try:
                response = self.dns_client.get_zone(zone_name, scope="GLOBAL")
            except oci.exceptions.ServiceError as err:
                if err.status == 404:
                    continue
                raise self._api_error(f"looking up zone {zone_name}", err) from err
            except (
                oci.exceptions.RequestException, oci.exceptions.ConnectTimeout, CircuitBreakerError
            ) as err:
                raise errors.PluginError(f"Unable to reach OCI DNS to look up {zone_name}.") from err
            zone = (response.data.id, zone_name)
            self._zones[record_name] = zone
            return zone

        raise _ZoneNotFound(
            f"No accessible OCI public DNS zone found for {record_name} "
            f"(certificate domain {domain}). Check the region and DNS permissions."
        )
