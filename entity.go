package session

import "time"

//LoginCandidate is a record of a login attempt
type LoginCandidate struct {
	SessionID     string     `json:"sessionid" datastore:"sessionid"`
	UserAccountID string     `json:"useraccountid" datastore:"useraccountid"`
	Email         string     `json:"email" datastore:"email"`
	RoleToken     string     `json:"roletoken" datastore:"roletoken"`
	Activated     bool       `json:"activated" datastore:"activated"`
	CreatedDate   *time.Time `json:"createddate,omitempty" datastore:"createddate"`
	ActivatedDate *time.Time `json:"activateddate,omitempty" datastore:"activateddate"`
}
