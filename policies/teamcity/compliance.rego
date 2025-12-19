package teamcity.compliance

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# Deny projects without description
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "teamcity_project"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    not after.description
    
    msg := sprintf(
        "TeamCity project '%s' must have a description",
        [resource.address]
    )
}

# Deny build configurations without description
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "teamcity_build_configuration"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    not after.description
    
    msg := sprintf(
        "TeamCity build configuration '%s' must have a description",
        [resource.address]
    )
}

# Warn on VCS roots without branch specification
warn contains msg if {
    resource := input.resource_changes[_]
    resource.type == "teamcity_vcsroot"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    not after.branch
    not after.branch_spec
    
    msg := sprintf(
        "TeamCity VCS root '%s' should specify branch or branch_spec",
        [resource.address]
    )
}

# Deny versioned settings without proper format
warn contains msg if {
    resource := input.resource_changes[_]
    resource.type == "teamcity_versioned_settings"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    after.format != "kotlin"
    after.format != "xml"
    
    msg := sprintf(
        "TeamCity versioned settings '%s' should use kotlin or xml format",
        [resource.address]
    )
}
