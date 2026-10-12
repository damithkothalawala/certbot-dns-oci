certbot-dns-oci
===============

Oracle Cloud Infrastructure (OCI) public DNS authenticator for Certbot.
The plugin adds DNS-01 TXT challenge values and removes each value after
validation using OCI's DNS API.

Requirements
------------

* Python 3.10 or newer.
* Certbot 5.x, ACME 5.x, and OCI Python SDK 2.187.2 or newer within the 2.x series.
* A public DNS zone hosted by OCI, with its authoritative nameservers configured
  at your registrar (or an appropriately delegated challenge zone).
* An OCI API signing key and a configuration profile with permission to read the
  zone and update its records in the configured region.

Version 0.2.0 targets Certbot 5.x. The plugin name ``dns-oci`` and the existing
configuration, profile, and propagation options are unchanged. Older Certbot
major versions are outside this release's supported range.

Installation
------------

Install Certbot and this plugin into the same virtual environment. This does not
install the plugin into a separate snap or operating-system Certbot installation.
The OCI CLI is optional; the plugin uses the OCI Python SDK directly.

.. code-block:: bash

    git clone https://github.com/damithkothalawala/certbot-dns-oci.git
    cd certbot-dns-oci
    python3 -m venv .venv
    .venv/bin/python -m pip install --upgrade pip
    .venv/bin/python -m pip install --upgrade 'certbot>=5,<6' 'acme>=5,<6' .
    .venv/bin/python -m pip check
    .venv/bin/certbot plugins --authenticators

The last command should list ``dns-oci``. Plugin discovery does not load OCI
credentials or contact OCI. Use this environment's ``certbot`` executable for
issuance and scheduled renewal.

To update an existing checkout and virtual environment:

.. code-block:: bash

    git pull --ff-only
    .venv/bin/python -m pip install --upgrade 'certbot>=5,<6' 'acme>=5,<6' .
    .venv/bin/python -m pip check
    .venv/bin/certbot --version

Dependency troubleshooting
--------------------------

`Upstream issue #4
<https://github.com/therealcmj/certbot-dns-oci/issues/4>`_ reports
``ImportError: cannot import name 'ClientBase' from 'acme.client'`` during
Certbot startup. Older Certbot code imports this class; ACME removed it in
`version 2.0.0
<https://github.com/certbot/certbot/blob/v4.0.0/certbot/CHANGELOG.md#200---2022-11-21>`_.
This is a Certbot/ACME compatibility problem before the plugin loads.

This release constrains both Certbot and ACME to major version 5 and removes the
old independent ``acme>=1.31.0`` requirement. Use the installation or upgrade
commands above to update them together in the same environment. Do not work
around that traceback by downgrading ACME to 1.x or using ``--no-deps``.
If another application pins an older Certbot, use a separate virtual environment
or update that application before installing this release. A successful
``pip check`` should be followed by ``certbot --version`` and
``certbot plugins --authenticators``; dependency metadata alone is not a startup
test.

Configuration
-------------

Create an `OCI SDK configuration file
<https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm>`_
with your actual account details. For example:

.. code-block:: ini

    [DEFAULT]
    user=ocid1.user.oc1..REPLACE_WITH_USER_OCID
    fingerprint=REPLACE_WITH_API_KEY_FINGERPRINT
    tenancy=ocid1.tenancy.oc1..REPLACE_WITH_TENANCY_OCID
    region=REPLACE_WITH_OCI_REGION
    key_file=/absolute/path/to/oci_api_key.pem

Use absolute paths for the configuration and signing key, and restrict both
files to the account running Certbot:

.. code-block:: bash

    chmod 600 /absolute/path/to/oci-config /absolute/path/to/oci_api_key.pem

``--dns-oci-config`` selects an explicit OCI configuration file;
``--dns-oci-profile`` selects its profile, defaulting to ``DEFAULT``.
When no file is specified, the plugin follows the OCI SDK search order:
``~/.oci/config``, then ``OCI_CONFIG_FILE`` if set, then
``~/.oraclebmc/config``. An explicitly selected missing file produces an error.
The resolved configuration path and profile are saved as plugin options for
Certbot renewal. Run renewal as an account that can read those files.

Arguments
---------

``--authenticator dns-oci`` or ``--dns-oci``
    Select the OCI DNS authenticator.

``--dns-oci-config /absolute/path/to/oci-config``
    Select the OCI SDK configuration file (optional).

``--dns-oci-profile PROFILE``
    Select a profile from the configuration file (default: ``DEFAULT``).

``--dns-oci-propagation-seconds SECONDS``
    Wait before requesting ACME validation (default: 15 seconds).
    Increase this when DNS updates need more time to become publicly visible.

Examples
--------

First test with the ACME staging server. Replace the example domain and paths
with your own values:

.. code-block:: bash

    .venv/bin/certbot certonly --test-cert \
        --authenticator dns-oci \
        --dns-oci-config /absolute/path/to/oci-config \
        --dns-oci-profile DEFAULT \
        --dns-oci-propagation-seconds 60 \
        -d example.com -d '*.example.com'

For a publicly trusted certificate, repeat without ``--test-cert``. After
issuance, verify renewal against staging:

.. code-block:: bash

    .venv/bin/certbot renew --dry-run

These issuance and renewal commands contact OCI and an ACME server and modify
challenge TXT records. They are deployment checks, separate from the offline
test suite below.

The plugin discovers public zones from the challenge name towards its parent
domains, including an exact delegated ``_acme-challenge`` zone. It does not follow
CNAME aliases. Each PATCH specifies the TXT value being added or removed; it does
not replace the entire record set. Cleanup logs a warning when OCI reports a
missing or inaccessible record or zone.

Development
-----------

.. code-block:: bash

    python3 -m venv .venv
    .venv/bin/python -m pip install --upgrade pip
    .venv/bin/python -m pip install -e '.[test]' build twine
    .venv/bin/python -m pytest
    .venv/bin/python -m build
    .venv/bin/python -m twine check dist/*

The tests use real Certbot challenge objects with mocked OCI API calls. They
cover configuration/profile selection, renewal paths, discovery and error
handling, simultaneous challenge values, and cleanup after partial failure.
GitHub Actions is configured to test Python 3.10 through 3.14 with the latest
Certbot 5.x, plus the minimum Certbot/ACME 5.0 pair. CI builds and installs the
wheel before testing plugin discovery and the challenge lifecycle.

Offline tests do not verify OCI IAM policies, public DNS propagation, or live
certificate issuance. Run the staging checks with your deployment credentials
before relying on automatic renewal.
