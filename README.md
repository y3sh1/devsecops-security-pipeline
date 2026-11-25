# DevSecOps Security Pipeline

A pull request can change how a health service logs headers, which Python packages it uses, or which user starts its container. This repository turns those changes into a repeatable merge decision using Semgrep CE and Trivy. The application and policy tests use the Python standard library.

## Run the service

From the repository root, run the following commands with Python 3.13 and Docker.

```sh
python -m unittest discover -s tests -v
docker build -t health-service service
docker run --rm -p 127.0.0.1:8080:8080 health-service
```

Open `http://127.0.0.1:8080/health` to receive `{"status": "ok"}`. An unknown route returns HTTP 404. For a Python-only run, start `python service/server.py` and open the same address.

## Run the gate

Put Semgrep CE 1.187.0 and Trivy 0.76.2 on PATH. Semgrep can be installed in a separate Python environment with `python -m pip install semgrep==1.187.0`. Use the matching Trivy binary for your platform from its upstream release. You can set `SEMGREP_BIN` and `TRIVY_BIN` to absolute executable paths. The initial Trivy run downloads the vulnerability database and checks bundle. [Trivy release](https://github.com/aquasecurity/trivy/releases/tag/v0.76.2)

```sh
python security/check.py
python security/demo.py
```

The first command scans the checkout and writes `reports/security.json`. Exit codes are 0 for a pass, 1 for a policy violation, and 2 for a scanner or report error. The CI job stops before building the image on either failure. GitHub Actions runs the job on pull requests, pushes to main, and manual dispatch. To enforce it on merges, make `security-gate` a required status check in the repository ruleset.

The second command stages the three changes below together in a temporary directory, scans the candidate, restores the service files and scans again. It compares the findings with the expected categories. The scanner reads the candidate's source, inventory and Dockerfile as files. The demo installs no candidate packages and starts no containers. Both decisions are saved under `reports/demo/`.

| Candidate change | Evidence to inspect | Repair |
| --- | --- | --- |
| Log the entire request header map | Semgrep records the source file, line and local rule ID | Record the header count |
| Add an unused, old PyYAML pin to the inventory | Trivy reports the package, installed version, advisory ID and available fixed version | Remove the unused dependency |
| End the Dockerfile with `USER root` | Trivy identifies the failed Dockerfile check | Restore the explicit runtime UID and GID |

See [the saved candidate decision](examples/before.json) and [the saved decision after repair](examples/after.json) for the results from running this demonstration.

## Merge policy

| Signal | Decision and rationale |
| --- | --- |
| Semgrep rule with ERROR severity | Block. The local rule targets logging an entire header collection, which may include cookies and authorization values. |
| Trivy secret finding, any severity | Block. A maintainer must establish whether the value is active. Reports retain the location and rule ID only. |
| Trivy dependency or failed configuration check rated HIGH or CRITICAL | Block. Remove the exposure, replace an affected package or adopt the fix before building. The rule applies even when the advisory lists no fixed version. |
| Lower-severity dependencies, configurations and Semgrep findings | Retain for review in the JSON artifact. |
| Failed tool, malformed data or Semgrep scan errors | Stop the job. An incomplete scan cannot establish a passing decision. |

The workflow grants read access to repository contents. It uploads only the normalized report. Raw tool JSON is temporary because scanner output may include code and matched secret text. To adapt this example to an existing service, keep the gate at the repository root, include the application's pinned dependency inventory, adapt the logging rule to its API, and change the final Docker build context.

## Investigating a false positive

The first version of the logging rule flagged `len(self.headers)` in the health handler. That expression logs a count. During a local Semgrep comparison, the broad rule produced one finding on the service at line 10. The reviewed rule produced zero there. It still detects the candidate's direct header argument in the demo. Reproduce the comparison against the same file with these commands.

```sh
semgrep scan --config demo/coarse-rule.yml service
semgrep scan --config security/rules.yml service
```

## Scope and limitations

The service is a teaching target. The source rule recognizes calls through Python's `logging` module and direct or dictionary-wrapped header arguments. An application using adapters or serialization helpers needs additional rule coverage. Trivy reads the dependencies listed in the manifest. A project with transitive dependencies needs a resolved inventory. The checks cover the checkout and Dockerfile. Operating-system packages in the built image need an additional image scan. [Trivy Python coverage](https://trivy.dev/docs/latest/coverage/language/python/)

Fresh advisory data and scanner checks can change finding counts. Review tool upgrades and their effect on the gate. Protect the workflow, policy script and rules with repository review controls when using this pattern in a shared codebase. The GitHub workflow also requires network access to PyPI, GitHub and the Trivy data registries.

## Attribution

The service, rule, policy, fixture inputs, tests and demonstration runner were written for this repository. Semgrep CE supplies Python matching. Trivy supplies vulnerability intelligence, secret detection and Dockerfile checks. GitHub provides the workflow runner and the checkout, setup-python and artifact actions. [Semgrep CI examples](https://semgrep.dev/docs/semgrep-ci/sample-ci-configs/) · [Trivy filesystem scanning](https://trivy.dev/docs/latest/target/filesystem/) · [GitHub Actions](https://docs.github.com/en/actions)
