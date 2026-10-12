"""Offline regressions for Certbot's public authenticator lifecycle and OCI DNS."""

import argparse
from types import SimpleNamespace
from unittest.mock import Mock, call

from acme import challenges, messages
from certbot import achallenges, configuration, errors
from circuitbreaker import CircuitBreaker, CircuitBreakerError
from cryptography.hazmat.primitives.asymmetric import rsa
import josepy
import oci
import pytest

from certbot_dns_oci import dns_oci


@pytest.fixture
def config_file(tmp_path):
    path = tmp_path / "oci-config"
    path.write_text("[DEFAULT]\n", encoding="utf-8")
    path.chmod(0o600)
    return path


@pytest.fixture
def authenticator(tmp_path):
    def create(config_path=None, profile=None):
        namespace = argparse.Namespace(
            config_dir=str(tmp_path / "config"),
            work_dir=str(tmp_path / "work"),
            logs_dir=str(tmp_path / "logs"),
            http01_port=80,
            https_port=443,
            domains=[],
            dns_oci_config=config_path,
            dns_oci_profile=profile,
            dns_oci_propagation_seconds=0,
        )
        return dns_oci.Authenticator(configuration.NamespaceConfig(namespace), "dns-oci")

    return create


@pytest.fixture
def credentials(monkeypatch):
    config = {"region": "test-region"}
    loader = Mock(return_value=config)
    validator = Mock()
    factory = Mock()
    monkeypatch.setattr(oci.config, "from_file", loader)
    monkeypatch.setattr(oci.config, "validate_config", validator)
    monkeypatch.setattr(dns_oci, "_OCIDNSClient", factory)
    return SimpleNamespace(config=config, loader=loader, validator=validator, factory=factory)


@pytest.fixture
def dns_client(monkeypatch):
    sdk_client = Mock()
    # Neither an empty patch response nor a missing response body is an error.
    sdk_client.patch_domain_records.return_value = SimpleNamespace(data=None)
    monkeypatch.setattr(oci.dns, "DnsClient", Mock(return_value=sdk_client))
    client = dns_oci._OCIDNSClient({"region": "test-region"})
    return client, sdk_client


def service_error(status):
    return oci.exceptions.ServiceError(
        status=status,
        code="NotAuthorizedOrNotFound" if status == 404 else "RequestFailed",
        headers={},
        message="Simulated OCI failure",
    )


def zone_response(name="example.com"):
    return SimpleNamespace(status=200, data=SimpleNamespace(id="ocid1.dns-zone.test", name=name))


def test_plugin_discovery_and_prepare_do_not_load_credentials(authenticator, credentials):
    plugin = authenticator()
    plugin.prepare()
    assert plugin.get_chall_pref("example.com") == [challenges.DNS01]
    assert plugin.more_info()
    credentials.loader.assert_not_called()
    credentials.factory.assert_not_called()


def test_explicit_config_profile_are_used_and_persisted_for_renewal(
    authenticator, config_file, credentials, monkeypatch
):
    monkeypatch.chdir(config_file.parent)
    plugin = authenticator(config_file.name, "PRODUCTION")

    plugin._setup_credentials()

    credentials.loader.assert_called_once_with(
        file_location=str(config_file), profile_name="PRODUCTION"
    )
    credentials.validator.assert_called_once_with(credentials.config)
    credentials.factory.assert_called_once_with(credentials.config)
    assert plugin.config.dns_oci_config == str(config_file)
    assert plugin.config.dns_oci_profile == "PRODUCTION"


def test_home_directory_is_expanded_and_default_profile_is_used(
    authenticator, config_file, credentials, monkeypatch
):
    expanduser = dns_oci.os.path.expanduser
    monkeypatch.setattr(
        dns_oci.os.path,
        "expanduser",
        lambda path: str(config_file) if path == "~/oci-config" else expanduser(path),
    )
    plugin = authenticator("~/oci-config")

    plugin._setup_credentials()

    credentials.loader.assert_called_once_with(
        file_location=str(config_file), profile_name="DEFAULT"
    )
    assert plugin.config.dns_oci_profile == "DEFAULT"


@pytest.mark.parametrize("source", ["default", "environment", "legacy"])
def test_sdk_default_config_path_precedence_is_preserved(
    authenticator, tmp_path, credentials, monkeypatch, source
):
    default = tmp_path / "default-config"
    environment = tmp_path / "environment-config"
    legacy = tmp_path / "legacy-config"
    monkeypatch.setattr(oci.config, "DEFAULT_LOCATION", str(default))
    monkeypatch.setattr(oci.config, "FALLBACK_DEFAULT_LOCATION", str(legacy))
    monkeypatch.delenv("OCI_CONFIG_FILE", raising=False)
    if source in ("default", "environment"):
        monkeypatch.setenv("OCI_CONFIG_FILE", str(environment))
        environment.write_text("[DEFAULT]\n", encoding="utf-8")
        environment.chmod(0o600)
    if source == "default":
        default.write_text("[DEFAULT]\n", encoding="utf-8")
        default.chmod(0o600)
    legacy.write_text("[DEFAULT]\n", encoding="utf-8")
    legacy.chmod(0o600)
    expected = {"default": default, "environment": environment, "legacy": legacy}[source]

    plugin = authenticator()
    plugin._setup_credentials()

    credentials.loader.assert_called_once_with(file_location=str(expected), profile_name="DEFAULT")
    assert plugin.config.dns_oci_config == str(expected)


def test_client_is_reused_for_all_challenges(authenticator, config_file, credentials):
    plugin = authenticator(str(config_file))
    plugin._setup_credentials()
    first = plugin._get_ocidns_client()
    second = plugin._get_ocidns_client()
    assert first is second is credentials.factory.return_value
    credentials.loader.assert_called_once()
    credentials.factory.assert_called_once()


@pytest.mark.parametrize("explicit_options", [False, True])
def test_real_certbot_renewal_file_retains_resolved_config_and_profile(
    config_file, credentials, monkeypatch, tmp_path, explicit_options
):
    # Certbot exposes its renewal serializer only through its internal package.
    # Exercise it with the real CLI parser and installed entry-point discovery.
    import configobj
    from certbot._internal import cli, storage
    from certbot._internal.plugins.disco import PluginsRegistry

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "helpful_parser", None)
    cli_config_file = tmp_path / "cli.ini"
    cli_config_file.write_text("", encoding="utf-8")
    args = [
        "certonly", "--config", str(cli_config_file),
        "--config-dir", str(tmp_path / "config"),
        "--work-dir", str(tmp_path / "work"),
        "--logs-dir", str(tmp_path / "logs"),
        "--authenticator", "dns-oci", "--dns-oci-propagation-seconds", "45",
        "--non-interactive", "-d", "example.com",
    ]
    if explicit_options:
        args.extend(["--dns-oci-config", config_file.name, "--dns-oci-profile", "RENEWAL"])
    else:
        monkeypatch.setattr(oci.config, "DEFAULT_LOCATION", str(tmp_path / "missing-default"))
        monkeypatch.setenv("OCI_CONFIG_FILE", str(config_file))
    config = cli.prepare_and_parse_args(PluginsRegistry.find_all(), args)
    plugin = dns_oci.Authenticator(config, "dns-oci")
    plugin._setup_credentials()
    target = {kind: str(tmp_path / "live" / (kind + ".pem")) for kind in storage.ALL_FOUR}

    renewal = storage.make_renewal_configobj(str(tmp_path / "archive"), target, config)
    renewal.filename = str(tmp_path / "renewal.conf")
    renewal.write()
    saved = configobj.ConfigObj(renewal.filename)["renewalparams"]

    assert saved["authenticator"] == "dns-oci"
    assert saved["dns_oci_config"] == str(config_file)
    assert saved["dns_oci_profile"] == ("RENEWAL" if explicit_options else "DEFAULT")
    assert saved["dns_oci_propagation_seconds"] == "45"


def test_missing_config_is_a_certbot_error(authenticator, tmp_path, credentials):
    plugin = authenticator(str(tmp_path / "does-not-exist"))
    with pytest.raises(errors.PluginError):
        plugin._setup_credentials()
    credentials.factory.assert_not_called()


@pytest.mark.parametrize(
    "failure", [oci.exceptions.InvalidConfig({"user": "missing"}), ValueError("invalid key")]
)
def test_invalid_oci_configuration_is_a_certbot_error(
    authenticator, config_file, credentials, failure
):
    credentials.validator.side_effect = failure
    plugin = authenticator(str(config_file))
    with pytest.raises(errors.PluginError):
        plugin._setup_credentials()
    credentials.factory.assert_not_called()


def test_configuration_error_does_not_echo_secret_content(
    authenticator, config_file, credentials, caplog
):
    secret = "PRIVATE-KEY-CONTENTS-MUST-NOT-APPEAR"
    credentials.loader.side_effect = ValueError(secret)
    plugin = authenticator(str(config_file))
    with pytest.raises(errors.PluginError) as error:
        plugin._setup_credentials()
    assert secret not in str(error.value)
    assert secret not in caplog.text
    assert "ValueError" in str(error.value)
    assert plugin._client is None


def test_insecure_config_permissions_produce_warning(
    authenticator, config_file, credentials, caplog
):
    config_file.chmod(0o644)
    authenticator(str(config_file))._setup_credentials()
    assert "Unsafe permissions" in caplog.text


def test_find_zone_prefers_delegated_challenge_zone(dns_client):
    client, sdk = dns_client
    name = "_acme-challenge.app.example.com"
    sdk.get_zone.return_value = zone_response(name)
    assert client._find_managed_zone("app.example.com", name) == (
        "ocid1.dns-zone.test", name
    )
    sdk.get_zone.assert_called_once_with(name, scope="GLOBAL")


def test_find_zone_walks_from_most_specific_to_parent(dns_client):
    client, sdk = dns_client
    sdk.get_zone.side_effect = [service_error(404), service_error(404), zone_response()]
    assert client._find_managed_zone("app.example.com", "_acme-challenge.app.example.com") == (
        "ocid1.dns-zone.test", "example.com"
    )
    assert sdk.get_zone.call_args_list == [
        call("_acme-challenge.app.example.com", scope="GLOBAL"),
        call("app.example.com", scope="GLOBAL"),
        call("example.com", scope="GLOBAL"),
    ]


@pytest.mark.parametrize("status", [401, 403, 429, 500])
def test_zone_api_errors_are_not_treated_as_missing_zones(dns_client, status):
    client, sdk = dns_client
    sdk.get_zone.side_effect = service_error(status)
    with pytest.raises(errors.PluginError):
        client._find_managed_zone("example.com", "_acme-challenge.example.com")
    sdk.get_zone.assert_called_once()


def test_zone_lookup_is_cached_and_normalized(dns_client):
    client, sdk = dns_client
    sdk.get_zone.return_value = zone_response()
    first = client._find_managed_zone("example.com", "_ACME-CHALLENGE.EXAMPLE.COM.")
    second = client._find_managed_zone("example.com", "_acme-challenge.example.com")
    assert first == second
    sdk.get_zone.assert_called_once_with("_acme-challenge.example.com", scope="GLOBAL")


def test_no_accessible_zone_is_a_certbot_error(dns_client):
    client, sdk = dns_client
    sdk.get_zone.side_effect = service_error(404)
    with pytest.raises(errors.PluginError):
        client.add_txt_record("example.com", "_acme-challenge.example.com", "value", 60)
    sdk.patch_domain_records.assert_not_called()


@pytest.mark.parametrize("operation", ["ADD", "REMOVE"])
def test_patch_uses_zone_ocid_and_only_the_requested_txt_value(dns_client, operation):
    client, sdk = dns_client
    sdk.get_zone.return_value = zone_response()
    owner = "_acme-challenge.example.com"
    if operation == "ADD":
        client.add_txt_record("example.com", owner, "token-value", 60)
    else:
        client.del_txt_record("example.com", owner, "token-value")

    args, kwargs = sdk.patch_domain_records.call_args
    assert args[:2] == ("ocid1.dns-zone.test", owner)
    assert kwargs == {"scope": "GLOBAL"}
    items = args[2].items
    assert len(items) == 1
    assert items[0].operation == operation
    assert items[0].domain == owner
    assert items[0].rtype == "TXT"
    assert items[0].rdata == "token-value"
    assert items[0].ttl == (60 if operation == "ADD" else None)


@pytest.mark.parametrize("method", ["add_txt_record", "del_txt_record"])
def test_patch_service_errors_are_certbot_errors(dns_client, method):
    client, sdk = dns_client
    sdk.get_zone.return_value = zone_response()
    sdk.patch_domain_records.side_effect = service_error(403)
    args = ["example.com", "_acme-challenge.example.com", "token-value"]
    if method == "add_txt_record":
        args.append(60)
    with pytest.raises(errors.PluginError) as error:
        getattr(client, method)(*args)
    assert "HTTP 403 (RequestFailed)" in str(error.value)
    action = "adding" if method == "add_txt_record" else "removing"
    assert action + " TXT record _acme-challenge.example.com" in str(error.value)


@pytest.mark.parametrize("method", ["_find_managed_zone", "add_txt_record", "del_txt_record"])
@pytest.mark.parametrize(
    "failure",
    [
        oci.exceptions.RequestException("connection failed"),
        oci.exceptions.ConnectTimeout("connection timed out"),
        CircuitBreakerError(CircuitBreaker(name="test-oci")),
    ],
    ids=["request-exception", "connect-timeout", "open-circuit"],
)
def test_connection_failure_is_a_certbot_error(dns_client, method, failure):
    client, sdk = dns_client
    sdk.get_zone.return_value = zone_response()
    sdk.patch_domain_records.side_effect = failure
    args = ["example.com", "_acme-challenge.example.com"]
    if method == "_find_managed_zone":
        sdk.get_zone.side_effect = failure
    else:
        args.append("token-value")
        if method == "add_txt_record":
            args.append(60)
    with pytest.raises(errors.PluginError, match="Unable to reach OCI DNS") as error:
        getattr(client, method)(*args)
    assert "_acme-challenge.example.com" in str(error.value)
    assert error.value.__cause__ is failure


def test_service_error_does_not_echo_request_body(dns_client, caplog):
    client, sdk = dns_client
    secret = "PRIVATE-REQUEST-CONTENTS-MUST-NOT-APPEAR"
    sdk.get_zone.side_effect = oci.exceptions.ServiceError(403, "NotAuthorized", {}, secret)
    with pytest.raises(errors.PluginError) as error:
        client._find_managed_zone("example.com", "_acme-challenge.example.com")
    assert secret not in str(error.value)
    assert secret not in caplog.text
    assert "403" in str(error.value)
    assert "NotAuthorized" in str(error.value)
    assert "looking up zone _acme-challenge.example.com" in str(error.value)


def test_cleanup_missing_zone_is_harmless(dns_client):
    client, sdk = dns_client
    sdk.get_zone.side_effect = service_error(404)
    client.del_txt_record("example.com", "_acme-challenge.example.com", "token-value")
    sdk.patch_domain_records.assert_not_called()


def test_cleanup_missing_record_is_harmless(dns_client):
    client, sdk = dns_client
    sdk.get_zone.return_value = zone_response()
    sdk.patch_domain_records.side_effect = service_error(404)
    client.del_txt_record("example.com", "_acme-challenge.example.com", "token-value")


def test_cleanup_before_perform_does_not_load_credentials(authenticator, credentials):
    authenticator().cleanup([])
    credentials.loader.assert_not_called()
    credentials.factory.assert_not_called()


def make_challenge(token, key):
    values = {
        "challb": messages.ChallengeBody(
            chall=challenges.DNS01(token=token),
            uri="https://acme.invalid/challenge/" + token.decode("ascii"),
            status=messages.STATUS_PENDING,
        ),
        "account_key": key,
    }
    # Certbot 5.0 used domain; newer versions use the ACME Identifier.
    if "identifier" in achallenges.KeyAuthorizationAnnotatedChallenge.__slots__:
        values["identifier"] = messages.Identifier(
            typ=messages.IDENTIFIER_FQDN, value="example.com"
        )
    else:
        values["domain"] = "example.com"
    return achallenges.KeyAuthorizationAnnotatedChallenge(**values)


@pytest.mark.parametrize("fail_second", [False, True])
def test_real_certbot_lifecycle_preserves_other_records_for_two_same_owner_challenges(
    authenticator, config_file, monkeypatch, fail_second
):
    sdk = Mock()
    monkeypatch.setattr(oci.config, "from_file", Mock(return_value={"region": "test-region"}))
    monkeypatch.setattr(oci.config, "validate_config", Mock())
    factory = Mock(return_value=sdk)
    monkeypatch.setattr(oci.dns, "DnsClient", factory)
    monkeypatch.setattr(dns_oci.dns_common.display_util, "notify", Mock())
    wait = Mock()
    monkeypatch.setattr(dns_oci.dns_common, "sleep", wait)
    owner = "_acme-challenge.example.com"
    records = {(owner, "TXT", "existing-other-validation"), ("www.example.com", "A", "192.0.2.1")}
    initial_records = records.copy()
    additions = []

    def get_zone(name, **kwargs):
        assert kwargs == {"scope": "GLOBAL"}
        if name != "example.com":
            raise service_error(404)
        return zone_response()

    def patch(zone_id, name, details, **kwargs):
        assert zone_id == "ocid1.dns-zone.test"
        assert name == owner
        assert kwargs == {"scope": "GLOBAL"}
        for item in details.items:
            record = (item.domain, item.rtype, item.rdata)
            if item.operation == "ADD":
                additions.append(record)
                if fail_second and len(additions) == 2:
                    raise service_error(500)
                records.add(record)
            elif item.operation == "REMOVE":
                records.discard(record)
            else:
                pytest.fail("Unexpected destructive patch operation: " + item.operation)
        return SimpleNamespace(data=SimpleNamespace(items=[]))

    sdk.get_zone.side_effect = get_zone
    sdk.patch_domain_records.side_effect = patch
    key = josepy.JWKRSA(key=rsa.generate_private_key(public_exponent=65537, key_size=2048))
    pending = [make_challenge(b"abcdefghijklmnop", key), make_challenge(b"qrstuvwxyz012345", key)]
    expected = {(owner, "TXT", chall.validation(key)) for chall in pending}
    assert len(expected) == 2
    plugin = authenticator(str(config_file))

    if fail_second:
        with pytest.raises(errors.PluginError):
            plugin.perform(pending)
        assert records == initial_records | {additions[0]}
        wait.assert_not_called()
    else:
        responses = plugin.perform(pending)
        assert len(responses) == 2
        assert all(isinstance(response, challenges.DNS01Response) for response in responses)
        assert records == initial_records | expected
        wait.assert_called_once_with(0)

    plugin.cleanup(pending)

    assert records == initial_records
    factory.assert_called_once()
    assert sdk.patch_domain_records.call_count == 4
