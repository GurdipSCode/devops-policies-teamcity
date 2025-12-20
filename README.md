# devops-policies-teamcity

Open Policy Agent (OPA) policies for validating Terraform configurations using the **teamcity** provider.

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
