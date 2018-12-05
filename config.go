package session

import (
	"log"
	"os"
	"strconv"

	lbcf "github.com/lidstromberg/config"

	"golang.org/x/net/context"
)

var (
	//EnvDebugOn controls verbose logging
	EnvDebugOn bool
	//EnvClientPool is the size of the client pool
	EnvClientPool int
)

const (
	//ConstJwtSessionHeaderElementTag session header element tag
	ConstJwtSessionHeaderElementTag = "sessionheader"
	//ConstJwtAppRoleElementTag role token element tag
	ConstJwtAppRoleElementTag = "roletokenid"
	//ConstJwtID id (session) element
	ConstJwtID = "jti"
	//ConstJwtRole roletoken id
	ConstJwtRole = "rle"
	//ConstJwtAccID account id
	ConstJwtAccID = "aid"
	//ConstJwtEml email
	ConstJwtEml = "eml"
)

//preflight config checks
func preflight(ctx context.Context, bc lbcf.ConfigSetting) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)
	log.Println("Started Session preflight..")

	//get the session config and apply it to the config
	bc.LoadConfigMap(ctx, preflightConfigLoader())

	//then check that we have everything we need
	if bc.GetConfigValue(ctx, "EnvDebugOn") == "" {
		log.Fatal("Could not parse environment variable EnvDebugOn")
	}

	if bc.GetConfigValue(ctx, "EnvSessTokenIssuer") == "" {
		log.Fatal("Could not parse environment variable EnvSessTokenIssuer")
	}

	if bc.GetConfigValue(ctx, "EnvSessExtensionMin") == "" {
		log.Fatal("Could not parse environment variable EnvSessExtensionMin")
	}

	if bc.GetConfigValue(ctx, "EnvSessAppRoleDelim") == "" {
		log.Fatal("Could not parse environment variable EnvSessAppRoleDelim")
	}

	//set the debug value
	constlog, err := strconv.ParseBool(bc.GetConfigValue(ctx, "EnvDebugOn"))

	if err != nil {
		log.Fatal("Could not parse environment variable EnvDebugOn")
	}

	EnvDebugOn = constlog

	log.Println("..Finished Session preflight.")
}

//preflightConfigLoader loads the session config vars
func preflightConfigLoader() map[string]string {
	cfm := make(map[string]string)

	//EnvDebugOn is the debug setting
	cfm["EnvDebugOn"] = os.Getenv("LB_DEBUGON")
	//EnvSessTokenIssuer is the issuer name which is embedded in the jwt
	cfm["EnvSessTokenIssuer"] = os.Getenv("JWT_ISSUER")
	//EnvSessExtensionMin is the number of minutes by which a token is extended on each touch
	cfm["EnvSessExtensionMin"] = os.Getenv("JWT_EXTMIN")
	//EnvSessAppRoleDelim is the delimiter character used when joining the user app roles in the jwt
	cfm["EnvSessAppRoleDelim"] = os.Getenv("JWT_APPROLEDELIM")

	if cfm["EnvDebugOn"] == "" {
		log.Fatal("Could not parse environment variable EnvDebugOn")
	}

	if cfm["EnvSessTokenIssuer"] == "" {
		log.Fatal("Could not parse environment variable EnvSessTokenIssuer")
	}

	if cfm["EnvSessExtensionMin"] == "" {
		log.Fatal("Could not parse environment variable EnvSessExtensionMin")
	}

	if cfm["EnvSessAppRoleDelim"] == "" {
		log.Fatal("Could not parse environment variable EnvSessAppRoleDelim")
	}

	return cfm
}
