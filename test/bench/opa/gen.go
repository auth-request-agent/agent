package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/auth-request-agent/agent/pkg/policy"
)

const regoTemplate = `package authz

import future.keywords

default allow_policy := false
default match_policy := false
default allow_default := false
default allow := false

x_source := input.http_request.headers["x-source"]
x_path := input.http_request.headers["x-path"]
x_method := input.http_request.headers["x-method"]

jwt_token := input.http_request.headers["jwt_token"]
jwt_x_source := concat(":", ["jwt", claims.name])

claims := payload {
	io.jwt.verify_hs256(jwt_token, "secret")
	[_, payload, _] := io.jwt.decode(jwt_token)
}

{{- range .PoliciesJwt.Policies }}
allow_policy if {
	jwt_x_source in {{ to_rego_arr .Allow }}
	x_path in {{ to_rego_arr .Uri }}
	x_method in {{ to_rego_arr .Methods }}
}

match_policy if {
	x_path in {{ to_rego_arr .Uri }}
	x_method in {{ to_rego_arr .Methods }}
}
{{- end }}

{{- range .PoliciesJson.Policies }}
allow_policy if {
	{{ index .Allow 0 }} == x_source
	x_path in {{ to_rego_arr .Uri }}
	x_method in {{ to_rego_arr .Methods }}
}

match_policy if {
	x_path in {{ to_rego_arr .Uri }}
	x_method in {{ to_rego_arr .Methods }}
}
{{- end }}

{{- range $pol := .PoliciesRegex.Policies }}
{{- range $uri := $pol.Uri }}
allow_policy if {
	x_source in {{ to_rego_arr $pol.Allow }}
	regex.match("{{$uri}}", x_path)
	x_method in {{ to_rego_arr $pol.Methods }}
}

match_policy if {
	regex.match("{{$uri}}", x_path)
	x_method in {{ to_rego_arr $pol.Methods }}
}
{{- end }}
{{- end }}

allow_default if {
	x_source in {{ to_rego_arr .PoliciesJwt.Default }}
}

allow if {
    allow_policy == true
}

allow if {
    match_policy == false
    allow_default == true
}
`

func to_rego_arr(arr []string) string {
	if len(arr) == 0 {
		return `[]`
	}

	return `["` + strings.Join(arr, `", "`) + `"]`
}

func genPolicy() {
	polJwt := policy.Config{}
	polJsonPath := policy.Config{}
	polRegex := policy.Config{}

	// jwt policies
	for p := 1; p < 10; p++ {
		uri := []string{}
		for u := 1; u < 10; u++ {
			uri = append(uri, fmt.Sprintf("/jwt_%d/%d", p, u))
		}
		polJwt.Policies = append(polJwt.Policies, policy.Policy{
			Uri:     uri,
			Methods: []string{"get"},
			Allow:   []string{"jwt:client1"},
		})
	}

	// jsonpath policies
	for p := 1; p < 10; p++ {
		uri := []string{}
		for u := 1; u < 10; u++ {
			uri = append(uri, fmt.Sprintf("/json_%d/%d", p, u))
		}
		polJsonPath.Policies = append(polJsonPath.Policies, policy.Policy{
			Uri:     uri,
			Methods: []string{"get"},
			Allow:   []string{fmt.Sprintf(`data["team%d"][_].name`, p)},
		})
	}

	// regex uri
	for p := 1; p < 10; p++ {
		uri := []string{}
		for u := 1; u < 10; u++ {
			uri = append(uri, fmt.Sprintf("^/regex_%d/[0-9]+/sub_%d/[0-9]+$", p, u))
		}
		polRegex.Policies = append(polRegex.Policies, policy.Policy{
			Uri:     uri,
			Methods: []string{"get"},
			Allow:   []string{"client1", "client2", "client2"},
		})
	}

	poldata := struct {
		PoliciesJwt   policy.Config
		PoliciesJson  policy.Config
		PoliciesRegex policy.Config
	}{
		PoliciesJwt:   polJwt,
		PoliciesJson:  polJsonPath,
		PoliciesRegex: polRegex,
	}

	tmpl, err := template.New("policy.rego").
		Funcs(template.FuncMap{
			"to_rego_arr": to_rego_arr,
		}).
		Parse(regoTemplate)
	if err != nil {
		panic(err)
	}

	var rego bytes.Buffer
	err = tmpl.Execute(&rego, poldata)
	if err != nil {
		panic(err)
	}

	if err := os.WriteFile("./bundle/policy.rego", rego.Bytes(), 0o777); err != nil {
		panic(err)
	}

	println("policy.rego done!")
}

func genData() {
	type item struct {
		Name    string `json:"name"`
		Age     int    `json:"age"`
		Surname string `json:"surname"`
		Phone   int    `json:"phone"`
		Org     string `json:"org"`
	}

	data := map[string][]item{}

	for t := 1; t < 100; t++ {
		tusers := []item{}
		for u := 1; u < 10; u++ {
			tusers = append(tusers, item{
				Name:    fmt.Sprintf("client%d", u),
				Age:     10,
				Surname: fmt.Sprintf("client_surname_%d", u),
				Phone:   11111111,
				Org:     fmt.Sprintf("org_%d", u),
			})
		}

		data[fmt.Sprintf("team%d", t)] = tusers
	}

	rdata, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		panic(err)
	}

	if err := os.WriteFile("./bundle/data.json", rdata, 0o777); err != nil {
		panic(err)
	}

	println("data.json done!")
}

func main() {
	genPolicy()
	genData()
}
