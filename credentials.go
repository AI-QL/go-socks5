package socks5

// CredentialStore is an interface used to support user/password authentication.
// It provides a method to validate a user and password combination.
type CredentialStore interface {
	// Valid checks if the given user and password combination is valid.
	// It returns true if the combination is valid, and false otherwise.
	Valid(user, password string) bool
}

// StaticCredentials is an implementation of the CredentialStore interface that uses a map to store user credentials.
// It enables direct use of a map as a credential store.
type StaticCredentials map[string]string

// Valid checks if the given user and password combination is valid.
// It returns true if the user exists in the map and the password matches, and false otherwise.
func (s StaticCredentials) Valid(user, password string) bool {
	pass, ok := s[user]
	if !ok {
		return false
	}
	return password == pass
}