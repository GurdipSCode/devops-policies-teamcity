package teamcity.naming

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# Deny projects with spaces in ID
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "teamcity_project"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    id := after.id
    contains(id, " ")
    
    msg := sprintf(
        "TeamCity project '%s' ID cannot contain spaces",
        [resource.address]
    )
}

# Deny build configurations with invalid ID format
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "teamcity_build_configuration"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    id := after.id
    not regex.match(`^[A-Za-z][A-Za-z0-9_]*$`, id)
    
    msg := sprintf(
        "TeamCity build configuration '%s' ID must start with letter and contain only alphanumeric/underscore",
        [resource.address]
    )
}

# Warn on agent pools with generic names
warn contains msg if {
    resource := input.resource_changes[_]
    resource.type == "teamcity_agent_pool"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    name := lower(after.name)
    generic := ["pool", "default", "agents", "test"]
    name in generic
    
    msg := sprintf(
        "TeamCity agent pool '%s' should have a descriptive name",
        [resource.address]
    )
}
