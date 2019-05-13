<a id="markdown-nexpose-asset-producer" name="nexpose-asset-producer"></a>
# nexpose-asset-producer - A service that produces scanned Nexpose assets to an event stream

<https://github.com/asecurityteam/nexpose-asset-producer>

<!-- TOC -->

- [nexpose-asset-producer](#nexpose-asset-producer)
    - [Overview](#overview)
    - [Quick Start](#quick-start)
    - [Configuration](#configuration)
    - [Status](#status)
    - [Contributing](#contributing)
        - [Building And Testing](#building-and-testing)
        - [Quality Gates](#quality-gates)
        - [License](#license)
        - [Contributing Agreement](#contributing-agreement)

<!-- /TOC -->

<a id="markdown-overview" name="overview"></a>
## Overview
This project is meant to be used with Nexpose. It provides a docker
image that when run, provides an endpoint that can be called with a
Site ID for a site that was recently scanned. The service will query the
Nexpose API with the Scan ID in order to get a list of assets that are
in that site, then produce each individual asset on an event stream.

This project is a part of a bigger project to Automate Nexpose Vulnerability
Scan results. The idea is that once a scan is run, the scan ID can be sent
to this nexpose-asset-producer, then once the nexpose-asset-producer puts
the asset on the event stream, it can be hydrated with vulnerability
information, including vulnerability details and solutions, which also
need to be queried from the Nexpose API, so that you can find out which
 vulnerabilities exist in your assets and how to fix them.
<Links to other references or material.>

<a id="markdown-quick-start" name="quick-start"></a>
## Quick Start

<Hello world style example.>

<a id="markdown-configuration" name="configuration"></a>
## Configuration

<Details of how to actually work with the project>

### Environment Variables
Here are the environment variables that need to be set
|Name              |Required | Description                                                    |Example                        |
|-----------------|:-------:|----------------------------------------------------------------|-------------------------------|
|NEXPOSE_HOST     |Yes      |Scheme and host for the Nexpose instance                        | https://nexpose.mycompany.com |
|NEXPOSE_USERNAME |Yes      |Username to access the Nexpose instance                         | myusername                    |
|NEXPOSE_PASSWORD |Yes      |Password that corresponds to the provided username              | mypassword                    |
|NEXPOSE_PAGESIZE |No       |The number of Nexpose assets to get back at a time (default 100)| 100                           |

<a id="markdown-status" name="status"></a>
## Status

This project is in incubation which means we are not yet operating this tool in production
and the interfaces are subject to change.

<a id="markdown-contributing" name="contributing"></a>
## Contributing

<a id="markdown-building-and-testing" name="building-and-testing"></a>
### Building And Testing

We publish a docker image called [SDCLI](https://github.com/asecurityteam/sdcli) that
bundles all of our build dependencies. It is used by the included Makefile to help make
building and testing a bit easier. The following actions are available through the Makefile:

-   make dep

    Install the project dependencies into a vendor directory

-   make lint

    Run our static analysis suite

-   make test

    Run unit tests and generate a coverage artifact

-   make integration

    Run integration tests and generate a coverage artifact

-   make coverage

    Report the combined coverage for unit and integration tests

-   make build

    Generate a local build of the project (if applicable)

-   make run

    Run a local instance of the project (if applicable)

-   make doc

    Generate the project code documentation and make it viewable
    locally.

<a id="markdown-quality-gates" name="quality-gates"></a>
### Quality Gates

Our build process will run the following checks before going green:

-   make lint
-   make test
-   make integration
-   make coverage (combined result must be 85% or above for the project)

Running these locally, will give early indicators of pass/fail.

<a id="markdown-license" name="license"></a>
### License

This project is licensed under Apache 2.0. See LICENSE.txt for details.

<a id="markdown-contributing-agreement" name="contributing-agreement"></a>
### Contributing Agreement

Atlassian requires signing a contributor's agreement before we can accept a
patch. If you are an individual you can fill out the
[individual CLA](https://na2.docusign.net/Member/PowerFormSigning.aspx?PowerFormId=3f94fbdc-2fbe-46ac-b14c-5d152700ae5d).
If you are contributing on behalf of your company then please fill out the
[corporate CLA](https://na2.docusign.net/Member/PowerFormSigning.aspx?PowerFormId=e1c17c66-ca4d-4aab-a953-2c231af4a20b).
