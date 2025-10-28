package auth

import (
	"context"
	"errors"
)

// Role constants
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
	RoleService  = "service" // For service-to-service communication
)

// Permission represents an action on a resource
type Permission struct {
	Resource string
	Action   string
}

// Common permissions
var (
	PermissionCertificateRead   = Permission{Resource: "certificate", Action: "read"}
	PermissionCertificateWrite  = Permission{Resource: "certificate", Action: "write"}
	PermissionCertificateRevoke = Permission{Resource: "certificate", Action: "revoke"}
	PermissionEnrollmentApprove = Permission{Resource: "enrollment", Action: "approve"}
	PermissionEnrollmentReject  = Permission{Resource: "enrollment", Action: "reject"}
	PermissionPolicyRead        = Permission{Resource: "policy", Action: "read"}
	PermissionPolicyWrite       = Permission{Resource: "policy", Action: "write"}
	PermissionAuditRead         = Permission{Resource: "audit", Action: "read"}
)

// RolePermissions defines permissions for each role
var RolePermissions = map[string][]Permission{
	RoleAdmin: {
		PermissionCertificateRead,
		PermissionCertificateWrite,
		PermissionCertificateRevoke,
		PermissionEnrollmentApprove,
		PermissionEnrollmentReject,
		PermissionPolicyRead,
		PermissionPolicyWrite,
		PermissionAuditRead,
	},
	RoleOperator: {
		PermissionCertificateRead,
		PermissionCertificateWrite,
		PermissionEnrollmentApprove,
		PermissionEnrollmentReject,
		PermissionPolicyRead,
	},
	RoleViewer: {
		PermissionCertificateRead,
		PermissionPolicyRead,
	},
	RoleService: {
		PermissionCertificateRead,
		PermissionCertificateWrite,
		PermissionCertificateRevoke,
	},
}

// ClaimsContextKey is the context key for JWT claims
type ClaimsContextKey struct{}

// GetClaimsFromContext extracts claims from context
func GetClaimsFromContext(ctx context.Context) (*Claims, error) {
	claims, ok := ctx.Value(ClaimsContextKey{}).(*Claims)
	if !ok {
		return nil, errors.New("no claims in context")
	}
	return claims, nil
}

// HasPermission checks if user has a specific permission
func HasPermission(claims *Claims, perm Permission) bool {
	for _, role := range claims.Roles {
		if perms, ok := RolePermissions[role]; ok {
			for _, p := range perms {
				if p.Resource == perm.Resource && p.Action == perm.Action {
					return true
				}
			}
		}
	}
	return false
}

// RequireRole checks if user has required role
func RequireRole(claims *Claims, roles ...string) bool {
	return claims.HasAnyRole(roles...)
}

// RequirePermission checks if user has required permission
func RequirePermission(ctx context.Context, perm Permission) error {
	claims, err := GetClaimsFromContext(ctx)
	if err != nil {
		return err
	}

	if !HasPermission(claims, perm) {
		return errors.New("permission denied")
	}

	return nil
}
