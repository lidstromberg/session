package session

import "errors"

//errors
var (
	//ErrKeyPairNotExist occurs if the key pair cannot be read
	ErrKeyPairNotExist = errors.New("keypair could not be created")
	//ErrJwtCouldNotParseToken error message
	ErrJwtCouldNotParseToken = errors.New("could not parse token, or token not valid")
	//ErrLoginSessionNotCreated failed to create session error
	ErrLoginSessionNotCreated = errors.New("could not create a login session")
	//ErrJwtInvalidSession error message
	ErrJwtInvalidSession = errors.New("session is no longer valid, please login")
)
