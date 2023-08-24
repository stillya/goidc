package user

type User struct {
	UserID     string                 `json:"user_id"`
	Username   string                 `json:"username"`
	Attributes map[string]interface{} `json:"attributes"`
	Enabled    bool                   `json:"enabled"`
}

func (u *User) SetAttr(key string, val interface{}) {
	if u.Attributes == nil {
		u.Attributes = map[string]interface{}{}
	}
	u.Attributes[key] = val
}
