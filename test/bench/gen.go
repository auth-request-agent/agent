package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/auth-request-agent/agent/pkg/policy"
	"gopkg.in/yaml.v3"
)

func genPolicy() {
	testPolicy := policy.Config{}

	cnHeader := "x-source"
	cnJwtHeader := "token"
	keyFilePath := "/jwt.key"

	testPolicy.Cn = []policy.Cn{
		{
			Prefix: "prefix:",
			Header: &cnHeader,
		},
		{
			Prefix: "jwt:",
			JWT: &policy.CnJWT{
				Payload: "user",
				Header:  &cnJwtHeader,
				KeyFile: &keyFilePath,
			},
		},
	}

	// jwt policies
	for p := 1; p < 10; p++ {
		uri := []string{}
		for u := 1; u < 10; u++ {
			uri = append(uri, fmt.Sprintf("/jwt_%d/%d", p, u))
		}
		testPolicy.Policies = append(testPolicy.Policies, policy.Policy{
			Uri:     uri,
			Methods: []string{"get"},
			Allow:   []string{"jwt:username"},
		})
	}

	// jsonpath policies
	for p := 1; p < 10; p++ {
		uri := []string{}
		for u := 1; u < 10; u++ {
			uri = append(uri, fmt.Sprintf("/json_%d/%d", p, u))
		}
		testPolicy.Policies = append(testPolicy.Policies, policy.Policy{
			Uri:     uri,
			Methods: []string{"get"},
			Allow:   []string{fmt.Sprintf("prefix:{.team%d[*].name}", p)},
		})
	}

	// regex uri
	for p := 1; p < 10; p++ {
		uri := []string{}
		for u := 1; u < 10; u++ {
			uri = append(uri, fmt.Sprintf("~/regex_%d/[0-9]+/sub_%d/[0-9]+", p, u))
		}
		testPolicy.Policies = append(testPolicy.Policies, policy.Policy{
			Uri:     uri,
			Methods: []string{"get"},
			Allow:   []string{fmt.Sprintf("prefix:{.team%d[*].name}", p)},
		})
	}

	testPolicy.Default = []string{"client"}

	config, err := yaml.Marshal(testPolicy)
	if err != nil {
		panic(err)
	}

	if err := os.WriteFile("./policy.yaml", config, 0o777); err != nil {
		panic(err)
	}

	println("policy.yaml done!")
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

	if err := os.WriteFile("./data.json", rdata, 0o777); err != nil {
		panic(err)
	}

	println("data.json done!")
}

func main() {
	genPolicy()
	genData()
}
