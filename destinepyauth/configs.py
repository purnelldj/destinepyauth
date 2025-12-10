#! /usr/bin/env python3
"""
Configuration model for DESP authentication.

This module defines the base configuration class that supports loading
settings via Conflator. Conflator can pull values from environment
variables and config files, and it can also be configured to accept
command-line arguments (the `CLIArg` metadata on fields documents the
flags to use when that mode is enabled).

Service-specific defaults are applied by the `ServiceRegistry` after
loading the configuration.
"""

from typing import Annotated

from conflator import CLIArg, ConfigModel, EnvVar
from pydantic import Field


class BaseConfig(ConfigModel):
    """
    Base configuration for DESP authentication.

        Fields support these Conflator-backed sources (when Conflator is used
        to load configuration):

        - Environment variables (names are defined with `EnvVar`, e.g. `USER`,
            `PASSWORD`, `IAM_URL`, `REALM`, `CLIENT_ID`, `REDIRECT_URI`)
        - Config files (for example: `~/.config/despauth/config.yaml`)
        - Command-line arguments (flags are documented with `CLIArg`, e.g.
            `-u/--user`, `--iam-url`) when Conflator is configured to parse
            CLI arguments.

    Service-specific defaults (iam_client, iam_redirect_uri) are applied
    by the ServiceRegistry after loading.
    """

    user: Annotated[
        str | None,
        Field(description="Your DESP username"),
        CLIArg("-u", "--user"),
        EnvVar("USER"),
    ] = None

    password: Annotated[
        str | None,
        Field(description="Your DESP password"),
        CLIArg("-p", "--password"),
        EnvVar("PASSWORD"),
    ] = None

    iam_url: Annotated[
        str,
        Field(description="The URL of the IAM server"),
        CLIArg("--iam-url"),
        EnvVar("IAM_URL"),
    ] = "https://auth.destine.eu"

    iam_realm: Annotated[
        str,
        Field(description="The realm of the IAM server"),
        CLIArg("--iam-realm"),
        EnvVar("REALM"),
    ] = "desp"

    iam_client: Annotated[
        str | None,
        Field(description="The client ID of the IAM server"),
        CLIArg("--iam-client"),
        EnvVar("CLIENT_ID"),
    ] = None

    iam_redirect_uri: Annotated[
        str | None,
        Field(description="Redirect URI"),
        CLIArg("--redirect-uri"),
        EnvVar("REDIRECT_URI"),
    ] = None
