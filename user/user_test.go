package user

import "testing"

func TestUser_SetAttr(t *testing.T) {
	type fields struct {
		UserID     string
		Username   string
		Attributes map[string]interface{}
		Disabled   bool
	}
	tests := []struct {
		name   string
		fields fields
	}{
		{
			name: "TestUser_SetAttr",
			fields: fields{
				UserID:     "test",
				Username:   "test",
				Attributes: make(map[string]interface{}),
				Disabled:   false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &User{
				UserID:     tt.fields.UserID,
				Username:   tt.fields.Username,
				Attributes: tt.fields.Attributes,
				Disabled:   tt.fields.Disabled,
			}
			u.SetAttr("test", "test")

			if u.Attributes["test"] != "test" {
				t.Errorf("SetAttr() error = %v", u.Attributes["test"])
				return
			}
		})
	}
}
