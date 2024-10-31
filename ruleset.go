package socks5

import (
	"context"
)

// RuleSet is an interface used to provide custom rules to allow or prohibit actions.
// It provides a method to determine whether a given request should be allowed.
type RuleSet interface {
	// Allow determines whether the given request should be allowed.
	// It returns a new context and a boolean indicating whether the request is allowed.
	Allow(ctx context.Context, req *Request) (context.Context, bool)
}

// PermitAll returns a RuleSet which allows all types of connections.
func PermitAll() RuleSet {
	return &PermitCommand{true, true, true}
}

// PermitNone returns a RuleSet which disallows all types of connections.
func PermitNone() RuleSet {
	return &PermitCommand{false, false, false}
}

// PermitCommand is an implementation of the RuleSet interface which enables filtering of supported commands.
type PermitCommand struct {
	// EnableConnect specifies whether the CONNECT command is allowed.
	EnableConnect bool

	// EnableBind specifies whether the BIND command is allowed.
	EnableBind bool

	// EnableAssociate specifies whether the ASSOCIATE command is allowed.
	EnableAssociate bool
}

// Allow determines whether the given request should be allowed based on the configured command rules.
// It returns a new context and a boolean indicating whether the request is allowed.
func (p *PermitCommand) Allow(ctx context.Context, req *Request) (context.Context, bool) {
	switch req.Command {
	case ConnectCommand:
		return ctx, p.EnableConnect
	case BindCommand:
		return ctx, p.EnableBind
	case AssociateCommand:
		return ctx, p.EnableAssociate
	default:
		return ctx, false
	}
}