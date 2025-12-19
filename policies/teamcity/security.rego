package teamcity.security

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# Deny VCS roots without authentication
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "teamcity_vcsroot"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    not after.auth
    not after.password
    not after.private_key
    
    msg := sprintf(
        "TeamCity VCS root '%s' must have authentication configured",
        [resource.address]
    )
}

# Deny VCS roots with plaintext passwords
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "teamcity_vcsroot"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    after.password
    not contains(after.password, "credentialsJSON:")
    
    msg := sprintf(
        "TeamCity VCS root '%s' should use credential parameters instead of plaintext passwords",
        [resource.address]
    )
}

# Deny build configurations with disabled artifact signing
warn contains msg if {
    resource := input.resource_changes[_]
    resource.type == "teamcity_build_configuration"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    contains(lower(after.name), "release")
    not after.settings
    
    msg := sprintf(
        "TeamCity release build '%s' should have artifact signing configured",
        [resource.address]
    )
}

# Deny projects without proper permissions
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "teamcity_project"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    not after.parent_project_id
    after.parent_project_id != "_Root"
    
    msg := sprintf(
        "TeamCity project '%s' must have a parent project for proper hierarchy",
        [resource.address]
    )
}

# Deny agent pools without authorized agents
warn contains msg if {
    resource := input.resource_changes[_]
    resource.type == "teamcity_agent_pool"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    not after.max_agents
    
    msg := sprintf(
        "TeamCity agent pool '%s' should set max_agents limit",
        [resource.address]
    )
}

# Deny global settings with insecure options
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "teamcity_global_settings"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    after.max_artifact_size == null
    
    msg := sprintf(
        "TeamCity global settings '%s' should configure max_artifact_size",
        [resource.address]
    )
}

# Deny build configs without cleanup rules
warn contains msg if {
    resource := input.resource_changes[_]
    resource.type == "teamcity_build_configuration"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    not after.cleanup
    
    msg := sprintf(
        "TeamCity build configuration '%s' should have cleanup rules configured",
        [resource.address]
    )
}

# Deny SSH keys without proper description
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "teamcity_ssh_key"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    not after.name
    
    msg := sprintf(
        "TeamCity SSH key '%s' must have a name for identification",
        [resource.address]
    )
}
