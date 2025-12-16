# Agent Context: LeftSize GitHub Action

## Repository Overview

**Purpose**: GitHub Action for running LeftSize cloud cost scans  
**Location**: `https://github.com/LeftSize/leftsize-action`  
**Type**: Docker-based GitHub Action (Linux only)  
**Distribution**: GitHub Marketplace (planned)

## Architecture

### Action Type

**Docker Container Action**:
- Runs on Linux runners only (ubuntu-latest, ubuntu-20.04, ubuntu-22.04)
- Uses Python 3.12 base image
- Includes Cloud Custodian and dependencies
- Self-contained, no external infrastructure required

### Entrypoint

```python
# run.py - Main action logic
1. Parse action inputs
2. Authenticate with cloud provider (Azure/AWS)
3. Run Cloud Custodian policies
4. Collect findings
5. Submit findings to LeftSize backend
6. Save findings as GitHub Action artifacts
7. Set action outputs
```

## Configuration

### Action Inputs

**Required**:
- `installation-id` - GitHub App installation ID (from onboarding)
- `repository-token` - Secure repository token (from onboarding)

**Optional**:
- `backend-url` - LeftSize backend API URL (default: `https://api.leftsize.com`)
- `cloud-provider` - Cloud provider: `azure` or `aws` (default: `azure`)
- `azure-subscription-ids` - Comma-separated Azure subscription IDs (default: all accessible)
- `aws-regions` - Comma-separated AWS regions (default: all accessible)
- `include-policies` - Policy categories: `cost-optimization`, `governance`, `security` (default: all)
- `exclude-policies` - Specific policy names to skip (default: none)
- `verbose` - Enable verbose logging (default: `false`)

### Action Outputs

- `findings-count` - Total number of findings detected
- `findings-submitted` - Whether findings were successfully submitted (`true`/`false`)
- `findings-json` - JSON string of all findings for custom processing

### Example Usage

```yaml
name: LeftSize Cost Optimization Scan

on:
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight
  workflow_dispatch:

permissions:
  id-token: write        # Required for OIDC
  contents: read

jobs:
  leftsize-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Azure Login (OIDC)
        uses: azure/login@v1
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
      
      - name: Run LeftSize Scan
        uses: leftsize/leftsize-action@v1
        with:
          installation-id: ${{ secrets.LEFTSIZE_INSTALLATION_ID }}
          repository-token: ${{ secrets.LEFTSIZE_REPOSITORY_TOKEN }}
```

## Cloud Custodian Integration

### Policy Structure

```
policies/
├── azure/
│   ├── cost-optimization/
│   │   ├── idle-vm.yml              # Idle virtual machines
│   │   ├── unattached-disk.yml      # Unattached managed disks
│   │   ├── unused-public-ip.yml     # Unused public IPs
│   │   ├── idle-app-service-plan.yml # Idle App Service Plans
│   │   └── inactive-load-balancer.yml # Inactive load balancers
│   ├── governance/
│   │   ├── missing-tags.yml         # Resources without tags
│   │   └── encryption.yml           # Unencrypted resources
│   └── security/
│       └── security-groups.yml      # Open security groups
└── aws/
    ├── cost-optimization/
    │   ├── idle-ec2.yml             # Idle EC2 instances
    │   ├── unattached-ebs.yml       # Unattached EBS volumes
    │   ├── unused-elastic-ip.yml    # Unused Elastic IPs
    │   └── old-snapshots.yml        # Old EBS snapshots
    └── governance/
        └── ... (similar structure)
```

### Policy Format

```yaml
# Example: policies/azure/cost-optimization/idle-vm.yml
policies:
  - name: leftsize-idle-vm
    description: Detect idle Azure Virtual Machines
    resource: azure.vm
    filters:
      - type: metric
        metric: Percentage CPU
        op: lt
        threshold: 5
        days: 7
      - type: value
        key: powerState
        op: eq
        value: "PowerState/running"
    metadata:
      category: cost-optimization
      severity: medium
      estimated_savings: 100  # Per month in USD
      safe_action: true
```

## Authentication

### Azure OIDC Setup

**Prerequisites**:
1. Azure AD App Registration with federated credentials
2. Reader + Monitoring Reader roles on subscriptions
3. GitHub secrets configured

**Federated Credential**:
```json
{
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:OWNER/REPO:ref:refs/heads/main",
  "audiences": ["api://AzureADTokenExchange"]
}
```

**GitHub Secrets**:
- `AZURE_CLIENT_ID` - App Registration client ID
- `AZURE_TENANT_ID` - Azure AD tenant ID
- `AZURE_SUBSCRIPTION_ID` - Subscription ID to scan
- `LEFTSIZE_INSTALLATION_ID` - From onboarding
- `LEFTSIZE_REPOSITORY_TOKEN` - From onboarding

### AWS OIDC Setup

**Prerequisites**:
1. IAM OIDC Provider for GitHub Actions
2. IAM Role with ReadOnlyAccess policy
3. GitHub secrets configured

**Trust Policy**:
```json
{
  "Effect": "Allow",
  "Principal": {
    "Federated": "arn:aws:iam::ACCOUNT-ID:oidc-provider/token.actions.githubusercontent.com"
  },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:OWNER/REPO:ref:refs/heads/main"
    }
  }
}
```

**GitHub Secrets**:
- `AWS_ROLE_ARN` - IAM role ARN to assume
- `LEFTSIZE_INSTALLATION_ID` - From onboarding
- `LEFTSIZE_REPOSITORY_TOKEN` - From onboarding

## Backend Integration

### API Endpoints

**Submit Findings**:
```http
POST https://api.leftsize.com/api/findings
Content-Type: application/json
X-Installation-Id: {installation-id}
X-Repository-Token: {repository-token}

{
  "repository": "owner/repo",
  "scan_time": "2025-12-15T19:00:00Z",
  "cloud_provider": "azure",
  "findings": [
    {
      "policy_name": "leftsize-idle-vm",
      "resource_id": "/subscriptions/.../resourceGroups/.../providers/Microsoft.Compute/virtualMachines/vm-1",
      "resource_name": "vm-1",
      "resource_type": "azure.vm",
      "severity": "medium",
      "category": "cost-optimization",
      "estimated_savings": 100,
      "details": { ... }
    }
  ]
}
```

**Response**:
```json
{
  "status": "success",
  "findings_received": 42,
  "issue_created": true,
  "issue_url": "https://github.com/owner/repo/issues/123"
}
```

## Development

### Local Testing

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export INPUT_INSTALLATION_ID=123456
export INPUT_REPOSITORY_TOKEN=token_abc123
export INPUT_CLOUD_PROVIDER=azure
export INPUT_VERBOSE=true

# Run locally (requires Azure/AWS credentials)
python run.py
```

### Docker Testing

```bash
# Build container
docker build -t leftsize-action .

# Run container
docker run --rm \
  -e INPUT_INSTALLATION_ID=123456 \
  -e INPUT_REPOSITORY_TOKEN=token_abc123 \
  -e INPUT_CLOUD_PROVIDER=azure \
  -e AZURE_CLIENT_ID=$AZURE_CLIENT_ID \
  -e AZURE_TENANT_ID=$AZURE_TENANT_ID \
  -e AZURE_SUBSCRIPTION_ID=$AZURE_SUBSCRIPTION_ID \
  leftsize-action
```

### Adding New Policies

1. Create YAML file in appropriate directory
2. Follow Cloud Custodian policy format
3. Add metadata (category, severity, savings estimate)
4. Test with `custodian validate`
5. Document in README

```bash
# Validate policy syntax
custodian validate policies/azure/cost-optimization/new-policy.yml

# Dry-run policy
custodian run --dryrun policies/azure/cost-optimization/new-policy.yml
```

## Dockerfile

```dockerfile
FROM python:3.12-slim

# Install Cloud Custodian
RUN pip install --no-cache-dir \
    c7n \
    c7n-azure \
    c7n-aws

# Copy policies and entrypoint
COPY policies /policies
COPY run.py /run.py
COPY requirements.txt /requirements.txt

# Install dependencies
RUN pip install --no-cache-dir -r /requirements.txt

ENTRYPOINT ["python", "/run.py"]
```

## Dependencies

```
# requirements.txt
c7n==0.9.x                 # Cloud Custodian core
c7n-azure==0.7.x          # Azure provider
c7n-aws==0.2.x            # AWS provider
requests==2.31.x          # HTTP client for backend API
pyyaml==6.0.x             # YAML parsing
azure-identity==1.15.x    # Azure authentication
azure-mgmt-monitor==6.0.x # Azure metrics
boto3==1.34.x             # AWS SDK
```

## Security

### Permissions Required

**Azure**:
- Reader (read resources)
- Monitoring Reader (read metrics)

**AWS**:
- ReadOnlyAccess (or custom read-only policy)

**GitHub**:
- `id-token: write` (for OIDC)
- `contents: read` (for action checkout)

### Safe by Default

- **No write operations** - All policies are read-only
- **No data exfiltration** - Findings sent to LeftSize backend only
- **Scoped tokens** - Repository token prevents cross-tenant attacks
- **OIDC authentication** - No long-lived secrets
- **Audit trail** - All scans logged in GitHub Actions

## Testing

### Unit Tests

```bash
# Run tests
pytest tests/

# Coverage report
pytest --cov=run --cov-report=html
```

### Integration Tests

```bash
# Test against real Azure/AWS (requires credentials)
pytest tests/integration/

# Mock backend responses
pytest tests/integration/ --mock-backend
```

## Distribution

### GitHub Marketplace

**Requirements**:
- `action.yml` metadata
- README with examples
- LICENSE file
- CHANGELOG
- Release tags (v1, v1.0, v1.0.0)

**Publishing**:
1. Tag release: `git tag -a v1.0.0 -m "Release v1.0.0"`
2. Push tag: `git push origin v1.0.0`
3. Create GitHub release with notes
4. Publish to Marketplace (automatic if tagged)

### Versioning

- **Major version**: `v1`, `v2` (breaking changes)
- **Minor version**: `v1.1`, `v1.2` (new features)
- **Patch version**: `v1.0.1`, `v1.0.2` (bug fixes)

**Users reference**: `uses: leftsize/leftsize-action@v1`

## Known Issues

1. **Linux runners only** - Docker actions don't work on Windows/macOS
2. **Long scan times** - Large subscriptions can take 5-10 minutes
3. **Rate limiting** - Cloud provider APIs may throttle requests
4. **Metrics data lag** - CPU metrics may be delayed by Azure/AWS

## Troubleshooting

### Authentication failures

```bash
# Azure: Test OIDC locally
az login --service-principal \
  --username $AZURE_CLIENT_ID \
  --tenant $AZURE_TENANT_ID \
  --federated-token $(curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL")

# AWS: Test OIDC locally
aws sts get-caller-identity
```

### No findings

**Possible causes**:
- Resources are well-optimized (good!)
- Policy filters too strict
- Insufficient permissions
- Metrics not available

**Debugging**:
- Run with `verbose: true`
- Check policy filters
- Verify Reader role assignment
- Test individual policies with `custodian run`

### Backend submission fails

**Possible causes**:
- Invalid installation ID or token
- Backend unreachable
- Findings format incorrect

**Debugging**:
- Check action outputs for error messages
- Verify secrets are set correctly
- Test backend endpoint with curl
- Check findings artifact in GitHub Actions

## Related Repositories

- **Backend API**: `https://github.com/LeftSize/leftsize`
- **Infrastructure**: `https://github.com/LeftSize/infra`
- **Website**: `https://github.com/LeftSize/website`

## Roadmap

**Current Status**: MVP - Basic scanning working

**Next Features**:
1. Cost estimation improvements (region-specific pricing)
2. More policy packs (GCP, security, compliance)
3. Custom policy support (user-defined)
4. Interactive approval flow (create PR instead of issue)
5. Baseline support (ignore known findings)
6. Scheduled remediation (auto-fix on schedule)
