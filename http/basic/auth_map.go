package basic

// AuthMap is a user and password pair
type AuthMap map[string]BasicAuthPair

// UserExists returns true if the user exists
func (m AuthMap) UserExists(user string) bool {
	_, ok := m[user]
	return ok
}

// Authenticate returns true if the user exists and the password is correct
func (m AuthMap) Authenticate(user, password string) (bool, error) {
	if m.UserExists(user) {
		return m[user].VerifyPassword(password)
	}
	return false, nil
}

// AddUserWithPlainPassword if user already exists it will over ride it
func (m AuthMap) AddUserWithPlainPassword(user, password string) {
	authPair, _ := NewBasicAuthPairWithPlainPassword(user, password)
	m[user] = authPair
}

// AddUserWithHashedPassword if user already exists it will over ride it
func (m AuthMap) AddUserWithHashedPassword(user, hashedPassword string) {
	m[user] = BasicAuthPair{User: user, HashedPassword: hashedPassword}
}
