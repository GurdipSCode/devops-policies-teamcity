package teamcity.security_test

import future.keywords.in
import data.teamcity.security

# Test: VCS root without auth should be denied
test_deny_vcsroot_without_auth {
    result := security.deny with input as {
        "resource_changes": [{
            "type": "teamcity_vcsroot",
            "address": "teamcity_vcsroot.test",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "test-vcs",
                    "auth": null,
                    "password": null,
                    "private_key": null
                }
            }
        }]
    }
    count(result) > 0
}

# Test: VCS root with auth should be allowed
test_allow_vcsroot_with_auth {
    result := security.deny with input as {
        "resource_changes": [{
            "type": "teamcity_vcsroot",
            "address": "teamcity_vcsroot.test",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "test-vcs",
                    "auth": "ssh",
                    "private_key": "credentialsJSON:key-id"
                }
            }
        }]
    }
    count(result) == 0
}

# Test: SSH key without name should be denied
test_deny_ssh_key_without_name {
    result := security.deny with input as {
        "resource_changes": [{
            "type": "teamcity_ssh_key",
            "address": "teamcity_ssh_key.test",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": null
                }
            }
        }]
    }
    count(result) > 0
}
