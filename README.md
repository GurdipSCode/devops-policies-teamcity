# devops-policies-teamcity

Open Policy Agent (OPA) policies for validating Terraform configurations using the **teamcity** provider.


[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![OPA](https://img.shields.io/badge/OPA-v0.68.0-blue?logo=openpolicyagent&logoColor=white)](https://www.openpolicyagent.org/)
[![Rego](https://img.shields.io/badge/Rego-v1-blueviolet)](https://www.openpolicyagent.org/docs/latest/policy-language/)
[![Terraform](https://img.shields.io/badge/Terraform-%3E%3D1.0-purple?logo=terraform&logoColor=white)](https://www.terraform.io/)

<!-- CI/CD Badges -->
[![CI](https://github.com/{owner}/{repo}/actions/workflows/ci.yml/badge.svg)](https://github.com/{owner}/{repo}/actions/workflows/ci.yml)
[![Release](https://github.com/{owner}/{repo}/actions/workflows/release.yml/badge.svg)](https://github.com/{owner}/{repo}/actions/workflows/release.yml)
[![Security Scan](https://github.com/{owner}/{repo}/actions/workflows/security.yml/badge.svg)](https://github.com/{owner}/{repo}/actions/workflows/security.yml)


[![CodeRabbit](https://img.shields.io/badge/CodeRabbit-AI%20Review-orange?logo=rabbitmq&logoColor=white)](https://coderabbit.ai/)
[![GitGuardian](https://img.shields.io/badge/GitGuardian-Secured-success?logo=gitguardian&logoColor=white)](https://www.gitguardian.com/)
[![Regal](https://img.shields.io/badge/Regal-Linted-green?logo=openpolicyagent&logoColor=white)](https://github.com/StyraInc/regal)
[![Conftest](https://img.shields.io/badge/Conftest-Tested-brightgreen)](https://www.conftest.dev/)


[![Latest Release](https://img.shields.io/github/v/release/{owner}/{repo}?include_prereleases&sort=semver)](https://github.com/{owner}/{repo}/releases)
[![Last Commit](https://img.shields.io/github/last-commit/{owner}/{repo})](https://github.com/{owner}/{repo}/commits/main)


[![Contributors](https://img.shields.io/github/contributors/{owner}/{repo})](https://github.com/{owner}/{repo}/graphs/contributors)
[![Issues](https://img.shields.io/github/issues/{owner}/{repo})](https://github.com/{owner}/{repo}/issues)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/{owner}/{repo}/pulls)
[![Stars](https://img.shields.io/github/stars/{owner}/{repo}?style=social)](https://github.com/{owner}/{repo}/stargazers)


## Overview

This repository contains Rego policies designed to enforce security, compliance, and best practices for Terraform resources managed by the [teamcity Terraform provider](https://registry.terraform.io/providers/teamcity).

## Features

- 🔒 Security policies for Teamcity resources
- ✅ Compliance validation rules
- 📋 Best practice enforcement
- 🚀 CI/CD integration ready

## Installation

```bash
git clone https://github.com/your-org/terraform-opa-teamcity.git
cd terraform-opa-teamcity
```

## Usage

### With Conftest

```bash
# Generate Terraform plan JSON
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Run policy checks
conftest test tfplan.json -p policies/
```

### With OPA

```bash
opa eval --data policies/ --input tfplan.json "data.teamcity.deny"
```

## Policy Structure

```
policies/
├── teamcity/
│   ├── security.rego      # Security-related policies
│   ├── compliance.rego    # Compliance policies
│   └── naming.rego        # Naming convention policies
└── lib/
    └── helpers.rego       # Shared helper functions
```

## Writing Custom Policies

Create a new `.rego` file in the `policies/teamcity/` directory:

```rego
package teamcity

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "teamcity_example_resource"
    # Add your policy logic here
    msg := "Policy violation message"
}
```

## Testing

```bash
# Run policy tests
opa test policies/ -v
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-policy`)
3. Commit your changes (`git commit -am 'Add new policy'`)
4. Push to the branch (`git push origin feature/new-policy`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Related Resources

- [Open Policy Agent Documentation](https://www.openpolicyagent.org/docs/)
- [Conftest](https://www.conftest.dev/)
- [Terraform Provider Registry](https://registry.terraform.io/)
