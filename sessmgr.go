package session

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/context"

	lbcf "github.com/lidstromberg/config"
	kp "github.com/lidstromberg/keypair"
	lblog "github.com/lidstromberg/log"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/segmentio/ksuid"
)

//SessMgr handles jwts
type SessMgr struct {
	Kp        *kp.KeyPair
	Bc        lbcf.ConfigSetting
	extendVal int
	issuer    string
}

//SessProvider defines the public operations of a session manager
type SessProvider interface {
	NewSession(ctx context.Context, userID, email, roleTokenID string) (string, error)
	CheckUserRole(ctx context.Context, sessionID string, roleName string) (bool, error)
	GetJwtClaim(ctx context.Context, sessionID string) (map[string]interface{}, error)
	GetJwtClaimElement(ctx context.Context, sessionID, element string) (interface{}, error)
	IsSessionValid(ctx context.Context, sessionID string) (bool, error)
	RefreshSession(ctx context.Context, sessionID string) <-chan interface{}
	SetAppClaim(ctx context.Context, sessionID string, appName string, appClaim string) (string, error)
	DeleteAppClaim(ctx context.Context, sessionID string, appName string) (string, error)
}

//MakeSessionMap sets the MapClaims custom map elements
func MakeSessionMap(userID, email, roletoken string) map[string]interface{} {
	shdr := make(map[string]interface{})

	shdr[ConstJwtID] = ksuid.New().String()
	shdr[ConstJwtRole] = roletoken
	shdr[ConstJwtAccID] = userID
	shdr[ConstJwtEml] = email

	return shdr
}

//DrainFn drains a channel until it is closed
func DrainFn(c <-chan interface{}) {
	for {
		select {
		case _, ok := <-c:
			if ok == false {
				return
			}
		}
	}
}

//PollFn processes either the error or the new session token
func PollFn(ctx context.Context, wg *sync.WaitGroup, sessid string, c <-chan interface{}) string {
	defer wg.Done()

	//keep the current session in case we have an error generating a new one
	newsess := sessid

	select {
	case <-ctx.Done():
		break
	case r, ok := <-c:
		if ok == false {
			break
		}
		if _, ok := r.(error); ok {
			err := r.(error)
			lblog.LogEvent("SvMgr", "pollFn", "error", err.Error())
			break
		}
		if _, ok := r.(string); ok {
			newsess = r.(string)
			break
		}
	}

	return newsess
}

//NewSessMgr creates a new credential manager
func NewSessMgr(ctx context.Context, bc lbcf.ConfigSetting, kpr *kp.KeyPair) (*SessMgr, error) {
	preflight(ctx, bc)

	if EnvDebugOn {
		lblog.LogEvent("SessMgr", "NewSessMgr", "info", "start")
	}

	ev, err := strconv.Atoi(bc.GetConfigValue(ctx, "EnvSessExtensionMin"))

	if err != nil {
		return nil, err
	}

	sm1 := &SessMgr{
		Kp:        kpr,
		Bc:        bc,
		extendVal: ev,
		issuer:    bc.GetConfigValue(ctx, "EnvSessTokenIssuer"),
	}

	if EnvDebugOn {
		lblog.LogEvent("SessMgr", "NewSessMgr", "info", "end")
	}

	return sm1, nil
}

//NewSession returns a signed jwt as a string
func (sessMgr *SessMgr) NewSession(ctx context.Context, userID, email, roleTokenID string) (string, error) {
	if EnvDebugOn {
		lblog.LogEvent("SessMgr", "NewSession", "info", "start")
	}

	//create a map of the values
	uky := MakeSessionMap(userID, email, roleTokenID)

	tokenstring, err := sessMgr.issueJwt(ctx, uky)

	if err != nil {
		return "", err
	}

	if EnvDebugOn {
		lblog.LogEvent("SessMgr", "NewSession", "info", "end")
	}

	return tokenstring, nil
}

//extractJwt converts a signed jwt string to a jwt token
func (sessMgr *SessMgr) extractJwt(sessionID string) (*jwt.Token, error) {
	if EnvDebugOn {
		lblog.LogEvent("SessMgr", "extractJwt", "info", "start")
	}

	token, err := jwt.Parse(sessionID, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return sessMgr.Kp.GetPubKey(), nil
	})

	if err != nil {
		return nil, err
	}

	//only return if the token is valid
	//sufficient to check iss, iat, nbf
	//each application should check its own appclaims
	if !token.Valid {
		return nil, ErrJwtInvalidSession
	}

	if EnvDebugOn {
		lblog.LogEvent("SessMgr", "extractJwt", "info", "end")
	}

	return token, nil
}

//checkRoleToken checks that targetClaims string exists in appRoleClaims string
func (sessMgr *SessMgr) checkRoleToken(appRoleClaims string, targetClaims string, delimiter string) bool {
	if EnvDebugOn {
		lblog.LogEvent("SessMgr", "checkRoleToken", "info", "start")
	}

	var targetLocated = false
	for _, element := range strings.Split(appRoleClaims, delimiter) {
		if element == targetClaims {
			targetLocated = true
			break
		}
	}

	if EnvDebugOn {
		lblog.LogEvent("SessMgr", "checkRoleToken", "info", "end")
	}

	return targetLocated
}

//issueJwt adds the jwt claim to the session header and returns the token string
func (sessMgr *SessMgr) issueJwt(ctx context.Context, sesshdr map[string]interface{}) (string, error) {
	if EnvDebugOn {
		lblog.LogEvent("SessMgr", "issueJwt", "info", "start")
	}

	now := time.Now()

	//create a map claims with the custom elements
	clms := jwt.MapClaims{
		"exp":         now.Add(time.Minute * time.Duration(sessMgr.extendVal)).Unix(),
		ConstJwtID:    sesshdr[ConstJwtID],
		"iss":         sessMgr.issuer,
		"nbf":         now.Unix(),
		"iat":         now.Unix(),
		ConstJwtRole:  sesshdr[ConstJwtRole],
		ConstJwtAccID: sesshdr[ConstJwtAccID],
		ConstJwtEml:   sesshdr[ConstJwtEml],
	}

	//wrap the token in a claims
	signer := jwt.NewWithClaims(jwt.SigningMethodRS256, clms)

	//sign the token
	tokenString, err := signer.SignedString(sessMgr.Kp.GetPriKey())

	if err != nil {
		return "", err
	}

	if EnvDebugOn {
		lblog.LogEvent("SessMgr", "issueJwt", "info", "end")
	}

	//return the jwt string
	return tokenString, nil
}

//CheckUserRole checks that the jwt authorises a given claim
func (sessMgr *SessMgr) CheckUserRole(ctx context.Context, sessionID string, roleName string) (bool, error) {
	if EnvDebugOn {
		lblog.LogEvent("SessMgr", "CheckUserRole", "info", "start")
	}

	//extract the token
	signer, err := sessMgr.extractJwt(sessionID)

	if err != nil {
		return false, err
	}

	//add/update the appclaim
	rle := signer.Claims.(jwt.MapClaims)[ConstJwtRole].(string)

	if sessMgr.checkRoleToken(rle, roleName, sessMgr.Bc.GetConfigValue(ctx, "EnvSessAppRoleDelim")) {
		return true, nil
	}

	if EnvDebugOn {
		lblog.LogEvent("SessMgr", "CheckUserRole", "info", "end")
	}

	return false, nil
}

//GetJwtClaim returns a decoded map[string]interface{} from the session string
func (sessMgr *SessMgr) GetJwtClaim(ctx context.Context, sessionID string) (map[string]interface{}, error) {
	if EnvDebugOn {
		lblog.LogEvent("SessMgr", "GetJwtClaim", "info", "start")
	}

	//extract the token
	signer, err := sessMgr.extractJwt(sessionID)

	if err != nil {
		return nil, err
	}

	//add/update the appclaim
	clm := signer.Claims.(jwt.MapClaims)

	if EnvDebugOn {
		lblog.LogEvent("SessMgr", "GetJwtClaim", "info", "end")
	}

	return clm, nil
}

//GetJwtClaimElement returns a decoded interface{} from the session string
func (sessMgr *SessMgr) GetJwtClaimElement(ctx context.Context, sessionID, element string) (interface{}, error) {
	if EnvDebugOn {
		lblog.LogEvent("SessMgr", "GetJwtClaimElement", "info", "start")
	}

	//extract the token
	signer, err := sessMgr.extractJwt(sessionID)

	if err != nil {
		return nil, err
	}

	//get the claim element
	clm, ok := signer.Claims.(jwt.MapClaims)[element]

	//if it doesn't exist then return error
	if !ok {
		return nil, ErrClaimElementNotExist
	}

	if EnvDebugOn {
		lblog.LogEvent("SessMgr", "GetJwtClaimElement", "info", "end")
	}

	return clm, nil
}

//IsSessionValid returns a bool indicating if the session is still valid
func (sessMgr *SessMgr) IsSessionValid(ctx context.Context, sessionID string) (bool, error) {
	if EnvDebugOn {
		lblog.LogEvent("SessMgr", "IsSessionValid", "info", "start")
	}

	//extract checks validity
	_, err := sessMgr.extractJwt(sessionID)

	if err != nil {
		return false, err
	}

	if EnvDebugOn {
		lblog.LogEvent("SessMgr", "IsSessionValid", "info", "end")
	}

	return true, nil
}

//RefreshSession exchanges a valid token for an extended life token
func (sessMgr *SessMgr) RefreshSession(ctx context.Context, sessionID string) <-chan interface{} {
	if EnvDebugOn {
		lblog.LogEvent("SessMgr", "RefreshSession", "info", "start")
	}

	//waitgroup to control goroutines
	var wg sync.WaitGroup

	//create the channels
	result := make(chan interface{})

	//mark the time
	exp := time.Now().Add(time.Minute * time.Duration(sessMgr.extendVal)).Unix()
	now := time.Now().Unix()

	//token renewal function
	rfn := func(sessid string) {
		sessionID := sessid

		defer wg.Done()

		//extract the token
		signer, err := sessMgr.extractJwt(sessionID)

		//send back the errors if any occur
		if err != nil {
			result <- err
			return
		}

		//extend the expiry
		signer.Claims.(jwt.MapClaims)["exp"] = exp
		signer.Claims.(jwt.MapClaims)["iat"] = now
		signer.Claims.(jwt.MapClaims)["nbf"] = now

		//sign the string again
		tokenString, err := signer.SignedString(sessMgr.Kp.GetPriKey())

		//send back the errors if any occur
		if err != nil {
			result <- err
			return
		}

		select {
		case <-ctx.Done():
			return
		case result <- tokenString:
			return
		}
	}

	wg.Add(1)
	go rfn(sessionID)

	go func() {
		wg.Wait()
		close(result)
	}()

	if EnvDebugOn {
		lblog.LogEvent("SessMgr", "RefreshSession", "info", "end")
	}

	return result
}

//SetAppClaim adds or updates an appclaim within the jwt (includes token refresh)
func (sessMgr *SessMgr) SetAppClaim(ctx context.Context, sessionID string, appName string, appClaim string) (string, error) {
	if EnvDebugOn {
		lblog.LogEvent("SessMgr", "SetAppClaim", "info", "start")
	}

	//extract the token
	signer, err := sessMgr.extractJwt(sessionID)

	if err != nil {
		return "", err
	}

	//add/update the appclaim
	signer.Claims.(jwt.MapClaims)[appName] = appClaim

	//sign the string again
	tokenString, err := signer.SignedString(sessMgr.Kp.GetPriKey())

	if err != nil {
		return "", err
	}

	if EnvDebugOn {
		lblog.LogEvent("SessMgr", "SetAppClaim", "info", "end")
	}

	return tokenString, nil
}

//DeleteAppClaim removes an appclaim within the jwt (includes token refresh)
func (sessMgr *SessMgr) DeleteAppClaim(ctx context.Context, sessionID string, appName string) (string, error) {
	if EnvDebugOn {
		lblog.LogEvent("SessMgr", "DeleteAppClaim", "info", "start")
	}

	//extract the token
	signer, err := sessMgr.extractJwt(sessionID)

	if err != nil {
		return "", err
	}

	//delete the appclaim
	delete(signer.Claims.(jwt.MapClaims), appName)

	//sign the string again
	tokenString, err := signer.SignedString(sessMgr.Kp.GetPriKey())

	if err != nil {
		return "", err
	}

	if EnvDebugOn {
		lblog.LogEvent("SessMgr", "DeleteAppClaim", "info", "end")
	}

	return tokenString, nil
}
