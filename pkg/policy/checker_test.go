// Copyright 2024 The AuthRequestAgent Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package policy

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/auth-request-agent/agent/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testCase struct {
	in              CheckInput
	allowed         bool
	wantedResultErr error
}

func Test_QueryInVars(t *testing.T) {
	config := `
cn:
  - header: "x-source1"
  - header: "x-source2"
    prefix: "prefix:"
vars:
  var1: ["{.team1[*].name}"]
policies:
  - uri: ["/endpoint1"]
    allow: ["$var1", "{.team2[*].name}", "client5"]
  - uri: ["/endpoint2"]
    allow: ["prefix:{.team1[*].name}"]`

	data := []byte(`{
  "team1": [
    {
      "name": "client1" 
    },
    {
      "name": "client2"
    }
  ],
  "team2": [
    {
      "name": "client3"
    },
    {
      "name": "client4" 
    }
  ]
}`)

	// from vars
	checker := NewChecker()
	require.NoError(t, checker.SetPolicy([]byte(config)))
	require.NoError(t, checker.SetData(data))

	result, err := checker.Check(CheckInput{
		Uri:     "/endpoint1",
		Method:  http.MethodGet,
		Headers: map[string]string{"x-source1": "client1"},
	})

	require.NoError(t, err)
	assert.Equal(t, true, result.Allow)

	// from query
	result, err = checker.Check(CheckInput{
		Uri:     "/endpoint1",
		Method:  http.MethodGet,
		Headers: map[string]string{"x-source1": "client1"},
	})

	assert.NoError(t, err)
	assert.Equal(t, true, result.Allow)

	// with prefix
	result, err = checker.Check(CheckInput{
		Uri:     "/endpoint2",
		Method:  http.MethodGet,
		Headers: map[string]string{"x-source2": "client1"},
	})

	assert.NoError(t, err)
	assert.Equal(t, true, result.Allow)
}

func Test_InvalidateData(t *testing.T) {
	config := `
cn:
  - header: "x-source"
policies:
  - uri: ["/endpoint"]
    allow: ["{.team[*].name}"]
`

	data := []byte(`{
"team": [
    {
      "name": "client1" 
    },
    {
      "name": "client2"
    }
  ]
}`)

	checker := NewChecker()
	require.NoError(t, checker.SetPolicy([]byte(config)))
	require.NoError(t, checker.SetData(data))

	result, err := checker.Check(CheckInput{
		Uri:     "/endpoint",
		Method:  http.MethodGet,
		Headers: map[string]string{"x-source": "client1"},
	})

	assert.NoError(t, err)
	assert.Equal(t, []string{"client1", "client2"}, checker.dataCache["{.team[*].name}"])
	assert.Equal(t, true, result.Allow)

	newData := []byte(`{
"team": [
    {
      "name": "client3" 
    },
    {
      "name": "client4"
    }
  ]
}`)

	require.NoError(t, checker.SetData(newData))
	assert.NotContains(t, checker.dataCache, "{.team[*].name}")

	result, err = checker.Check(CheckInput{
		Uri:     "/endpoint",
		Method:  http.MethodGet,
		Headers: map[string]string{"x-source": "client1"},
	})

	assert.Equal(t, []string{"client3", "client4"}, checker.dataCache["{.team[*].name}"])
	assert.NoError(t, err)
	assert.Equal(t, false, result.Allow)
}

func Test_Data(t *testing.T) {
	config := `
cn:
  - header: "x-source1"
  - header: "x-source2"
    prefix: "prefix:"
vars:
  var1: ["{.team2[*].name}"]
policies:
  - uri: ["/ep1"]
    allow: ["{.team1[*].name}"]
  - uri: ["/ep2"]
    allow: ["prefix:{.team2[*].name}"]
  - uri: ["/ep3"]
    allow: ["$var1"]
  - uri: ["/ep4"]
    allow: ["{.team3[*].name}"]
`

	data := []byte(`{
  "team1": [
    {
      "name": "client1" 
    },
    {
      "name": "client2"
    }
  ],
  "team2": [
    {
      "name": "client3"
    },
    {
      "name": "client4" 
    }
  ]
}`)

	checker := NewChecker()
	require.NoError(t, checker.SetPolicy([]byte(config)))
	require.NoError(t, checker.SetData(data))

	cases := []testCase{
		{
			in: CheckInput{
				Uri:     "/ep1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source1": "client1"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/ep1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source1": "client2"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/ep1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source1": "client3"},
			},
			allowed: false,
		},
		// prefix
		{
			in: CheckInput{
				Uri:     "/ep2",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source2": "client3"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/ep2",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source2": "client4"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/ep2",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source1": "client2"},
			},
			allowed: false,
		},
		// vars
		{
			in: CheckInput{
				Uri:     "/ep3",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source1": "client3"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/ep3",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source1": "client4"},
			},
			allowed: true,
		},
		// data not found
		{
			in: CheckInput{
				Uri:     "/ep4",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source1": "client3"},
			},
			allowed:         false,
			wantedResultErr: errors.New("jsonpath finding results failure: team3 is not found"),
		},
	}

	for _, c := range cases {
		result, err := checker.Check(c.in)
		assert.NoError(t, err)
		assert.Equal(t, c.allowed, result.Allow, "url: %s, method: %s", c.in.Uri, c.in.Method)
		assert.Equal(t, c.wantedResultErr, result.Err)
	}
}

func Test_Vars(t *testing.T) {
	config := `
cn:
  - header: "x-source1"
  - header: "x-source2"
    prefix: "prefix:"
vars:
  var1: ["client1"]
  var2: ["client2"]
  var3: ["prefix:client3"]
policies:
  - uri: ["/ep1"]
    allow: ["$var1"]
  - uri: ["/ep2"]
    allow: ["$var2", "$var3"]`

	checker := NewChecker()
	require.NoError(t, checker.SetPolicy([]byte(config)))

	cases := []testCase{
		{
			in: CheckInput{
				Uri:     "/ep1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source1": "client1"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/ep1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source1": "client2"},
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/ep2",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source1": "client2"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:    "/ep2",
				Method: http.MethodGet,
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/ep2",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source2": "client3"},
			},
			allowed: true,
		},
	}

	for _, c := range cases {
		result, err := checker.Check(c.in)
		assert.NoError(t, err)
		assert.Equal(t, c.allowed, result.Allow, "url: %s, method: %s, x-source: %s", c.in.Uri, c.in.Method, c.in.Headers["x-source"])
	}
}

func Test_ClientNameWildCard(t *testing.T) {
	config := `
cn:
  - header: "x-source1"
  - header: "x-source2"
    prefix: "prefix:"
policies:
  - uri: ["/ep1"]
    allow: ["prefix:*"]
  - uri: ["/ep2"]
    allow: ["*"]`

	checker := NewChecker()
	require.NoError(t, checker.SetPolicy([]byte(config)))

	cases := []testCase{
		{
			in: CheckInput{
				Uri:     "/ep1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source2": "client1"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/ep1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source2": "client2"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/ep1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source3": "client3"},
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/ep2",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source1": "client1"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/ep2",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source2": "client1"},
			},
			allowed: false,
		},
	}

	for _, c := range cases {
		result, err := checker.Check(c.in)
		assert.NoError(t, err)
		assert.Equal(t, c.allowed, result.Allow, "url: %s, method: %s, x-source: %s", c.in.Uri, c.in.Method, c.in.Headers["x-source"])
	}
}

func Test_JWT_TokenValidation(t *testing.T) {
	rootDir, cleanFs, err := util.MakeTmpFs("", t.Name(), map[string][]byte{
		"/keyfile1.key": []byte("secret"),
		"/keyfile2.key": []byte("invalid_secret"),
	})
	require.NoError(t, err)
	defer cleanFs()

	config := `
cn:
  - jwt: 
      payload: "user"
      header: "Auth1"
      keyFile: "` + rootDir + `/keyfile1.key"
    prefix: "jwt1:"
  - jwt: 
      payload: "user"
      header: "Auth2"
      keyFile: "` + rootDir + `/keyfile2.key"
    prefix: "jwt2:"
policies:
  - uri: ["/ep1"]
    allow: ["jwt1:jhon", "jwt2:jhon"]`

	checker := NewChecker()
	require.NoError(t, checker.SetPolicy([]byte(config)))

	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiamhvbiJ9.RO0UD8zn-NRJ7XlIuQMfeyoxLclFPF7N5PRkIJMgsck" // payload with user:jhon

	cases := []testCase{
		{
			in: CheckInput{
				Uri:     "/ep1",
				Headers: map[string]string{"Auth1": jwt},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/ep1",
				Headers: map[string]string{"Auth2": jwt},
			},
			wantedResultErr: ErrInvalidClientName{
				errMessage: "parse jwt token: token signature is invalid: signature is invalid",
			},
			allowed: false,
		},
	}

	for _, c := range cases {
		result, err := checker.Check(c.in)
		require.NoError(t, err)
		if c.wantedResultErr != nil {
			require.EqualError(t, c.wantedResultErr, result.Err.Error(), result.ClientName)
		} else {
			require.NoError(t, result.Err)
		}
		assert.Equal(t, c.allowed, result.Allow, result.ClientName)
	}
}

func Test_JWT_PayloadParser(t *testing.T) {
	config := `
cn:
  - header: "x-source"
  - jwt: 
      payload: "user"
      header: "Authorization"
    prefix: "jwt:"
  - jwt:
      payload: "user"
      cookie: "jwt"
    prefix: "cookie:"
policies:
  - uri: ["/ep1"]
    allow: ["jwt:jhon", "cookie:jhon"]
  - uri: ["/ep2"]
    allow: ["jessica"]`

	checker := NewChecker()
	require.NoError(t, checker.SetPolicy([]byte(config)))

	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiamhvbiJ9.aFR_EpsSSaquZiO8ow8ygy_RvNyMBPfBMPnNA9jyEDM" // payload with user:jhon

	cases := []testCase{
		{
			in: CheckInput{
				Uri:     "/ep1",
				Headers: map[string]string{"Cookie": "some-cookie=test; jwt=" + jwt},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/ep1",
				Headers: map[string]string{"x-source": "client1"},
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/ep2",
				Headers: map[string]string{"Authorization": jwt},
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/ep1",
				Headers: map[string]string{"Authorization": jwt},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/ep1",
				Headers: map[string]string{"Authorization": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7Im5hbWUiOiJqaG9uIn19.Jk_NZmxy5LkxGjS_dhvDq-yXxvTs6xSNxErHoen9qhs"},
			},
			allowed: false,
			wantedResultErr: ErrInvalidClientName{
				errMessage: fmt.Sprintf(errPayloadFieldIsntStringType, "user", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7Im5hbWUiOiJqaG9uIn19.Jk_NZmxy5LkxGjS_dhvDq-yXxvTs6xSNxErHoen9qhs"),
			},
		},
	}

	for _, c := range cases {
		result, err := checker.Check(c.in)
		require.NoError(t, err)
		if c.wantedResultErr != nil {
			require.EqualError(t, c.wantedResultErr, result.Err.Error())
		} else {
			require.NoError(t, result.Err)
		}
		assert.Equal(t, c.allowed, result.Allow, "url: %s, method: %s, parsed client name: %s, headers: %s", c.in.Uri, c.in.Method, result.ClientName, c.in.Headers)
	}
}

func Test_DefaultPolicy(t *testing.T) {
	config := `
cn:
  - header: "x-source"
default:
  - client1`

	checker := NewChecker()
	require.NoError(t, checker.SetPolicy([]byte(config)))

	cases := []testCase{
		{
			in: CheckInput{
				Uri:     "/get",
				Headers: map[string]string{"x-source": "client1"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/get",
				Headers: map[string]string{"x-source": "client2"},
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/get",
				Headers: map[string]string{"x-source1": "client1"},
			},
			allowed: false,
		},
	}

	for _, c := range cases {
		result, err := checker.Check(c.in)
		assert.NoError(t, err)
		assert.Equal(t, c.allowed, result.Allow)
	}
}

func Test_CnPriority(t *testing.T) {
	config := `
cn:
  - header: "x-source1"
  - header: "x-source2"
    prefix: "prefix:"
policies:
  - uri: ["/ep1"]
    method: ["get"]
    allow: ["prefix:client1"]`

	checker := NewChecker()
	require.NoError(t, checker.SetPolicy([]byte(config)))

	cases := []testCase{
		{
			in: CheckInput{
				Uri:     "/ep1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source1": "client2", "x-source2": "client1"},
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/ep1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source2": "client1"},
			},
			allowed: true,
		},
	}

	for _, c := range cases {
		result, err := checker.Check(c.in)
		assert.NoError(t, err)
		assert.Equal(t, c.allowed, result.Allow, "url: %s, method: %s, x-source: %s", c.in.Uri, c.in.Method, c.in.Headers["x-source"])
	}
}

func Test_MatchWithoutMethod(t *testing.T) {
	config := `
cn:
  - header: "x-source"
policies:
  - uri: ["/user"]
    allow: ["client1"]
  - uri: ["~/info"]
    allow: ["client2"]`

	checker := NewChecker()
	require.NoError(t, checker.SetPolicy([]byte(config)))

	cases := []testCase{
		{
			in: CheckInput{
				Uri:     "/user",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client1"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/user",
				Method:  http.MethodDelete,
				Headers: map[string]string{"x-source": "client1"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/info",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client2"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/info",
				Method:  http.MethodDelete,
				Headers: map[string]string{"x-source": "client2"},
			},
			allowed: true,
		},
	}

	for _, c := range cases {
		result, err := checker.Check(c.in)
		assert.NoError(t, err)
		assert.Equal(t, c.allowed, result.Allow, "url: %s, method: %s, x-source: %s", c.in.Uri, c.in.Method, c.in.Headers["x-source"])
	}
}

func Test_MatchSimpleUri(t *testing.T) {
	config := `
cn:
  - header: "x-source"
policies:
  - uri: ["/user"]
    method: ["get"]
    allow: ["client2"]
  - uri: ["/user"]
    method: ["put"]
    allow: ["client3"]`

	checker := NewChecker()
	require.NoError(t, checker.SetPolicy([]byte(config)))

	cases := []testCase{
		// get
		{
			in: CheckInput{
				Uri:     "/user",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client1"},
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/user",
				Method:  http.MethodPut,
				Headers: map[string]string{"x-source": "client2"},
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/user",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client2"},
			},
			allowed: true,
		},
		// put
		{
			in: CheckInput{
				Uri:     "/user",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client3"},
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/user",
				Method:  http.MethodPut,
				Headers: map[string]string{"x-source": "client3"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/user",
				Method:  http.MethodPut,
				Headers: map[string]string{"x-source": "client2"},
			},
			allowed: false,
		},
	}

	for _, c := range cases {
		result, err := checker.Check(c.in)
		assert.NoError(t, err)
		assert.Equal(t, c.allowed, result.Allow, "url: %s, method: %s, x-source: %s", c.in.Uri, c.in.Method, c.in.Headers["x-source"])
	}
}

func Test_PolicyPrioriy_RegexVsSimple(t *testing.T) {
	config := `
cn:
  - header: "x-source"
policies:
  - uri: ["~/user/[0-9]+"]
    method: ["get"]
    allow: ["client1"]
  - uri: ["/user/1"]
    method: ["get"]
    allow: ["client2"]`

	checker := NewChecker()
	require.NoError(t, checker.SetPolicy([]byte(config)))

	cases := []testCase{
		{
			in: CheckInput{
				Uri:     "/user/1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client2"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/user/1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client1"},
			},
			allowed: false,
		},
	}

	for _, c := range cases {
		result, err := checker.Check(c.in)
		assert.NoError(t, err)
		assert.Equal(t, c.allowed, result.Allow, "url: %s, method: %s, x-source: %s", c.in.Uri, c.in.Method, c.in.Headers["x-source"])
	}
}

func Test_PolicyPrioriy_RegexVsRegex(t *testing.T) {
	config := `
cn:
  - header: "x-source"
policies:
  - uri: ["~/us(.+)"]
    method: ["get"]
    allow: ["client1"]
  - uri: ["~/user/[0-9]+"]
    method: ["get"]
    allow: ["client2"]`

	checker := NewChecker()
	require.NoError(t, checker.SetPolicy([]byte(config)))

	cases := []testCase{
		{
			in: CheckInput{
				Uri:     "/user/1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client2"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/user/1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client1"},
			},
			allowed: false,
		},
	}

	for _, c := range cases {
		result, err := checker.Check(c.in)
		assert.NoError(t, err)
		assert.Equal(t, c.allowed, result.Allow, "url: %s, method: %s, x-source: %s", c.in.Uri, c.in.Method, c.in.Headers["x-source"])
	}
}

func Test_MatchRegexpUri(t *testing.T) {
	config := `
cn:
  - header: "x-source"
policies:
  - uri: ["~/user/[0-9]+", "~/order/[0-9]+/info"]
    method: ["get"]
    allow: ["client2"]
  - uri: ["~/user/[0-9]+"]
    method: ["post"]
    allow: ["client3"]`

	checker := NewChecker()
	require.NoError(t, checker.SetPolicy([]byte(config)))

	cases := []testCase{
		// GET user/*
		{
			in: CheckInput{
				Uri:     "/user/1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client2"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/order/1/info",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client2"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/user/1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client1"},
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/order/1/info",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client1"},
			},
			allowed: false,
		},
		// POST user/*
		{
			in: CheckInput{
				Uri:     "/user/1",
				Method:  http.MethodPost,
				Headers: map[string]string{"x-source": "client1"},
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/user/1",
				Method:  http.MethodPost,
				Headers: map[string]string{"x-source": "client3"},
			},
			allowed: true,
		},
		// denied
		{
			in: CheckInput{
				Uri:     "/user/1",
				Method:  http.MethodPost,
				Headers: map[string]string{"x-source": "client1"},
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/user/1",
				Method:  http.MethodPost,
				Headers: map[string]string{"x-source": "client3"},
			},
			allowed: true,
		},
	}

	for _, c := range cases {
		result, err := checker.Check(c.in)
		assert.NoError(t, err)
		assert.Equal(t, c.allowed, result.Allow, "url: %s, method: %s, x-source: %s", c.in.Uri, c.in.Method, c.in.Headers["x-source"])
	}
}
