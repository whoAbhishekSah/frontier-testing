package main

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/raystack/frontier/pkg/utils"
	frontierv1beta1 "github.com/raystack/frontier/proto/v1beta1"
)

type ServiceUserTokenGenerator func() ([]byte, error)

func GetServiceUserTokenGenerator(credential *frontierv1beta1.KeyCredential) (ServiceUserTokenGenerator, error) {
	// generate a token out of key
	rsaKey, err := jwk.ParseKey([]byte(credential.GetPrivateKey()), jwk.WithPEM(true))
	if err != nil {
		return nil, err
	}
	if err = rsaKey.Set(jwk.KeyIDKey, credential.GetKid()); err != nil {
		return nil, err
	}
	return func() ([]byte, error) {
		return utils.BuildToken(rsaKey, "abhishek-made-this", credential.GetPrincipalId(), time.Hour*12, nil)
	}, nil
}

func main2() {
	cred := &frontierv1beta1.KeyCredential{
		PrivateKey:  "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n",
		Type:        "type",
		Kid:         "kid",
		PrincipalId: "principal_id",
	}

	gen, err := GetServiceUserTokenGenerator(cred)
	if err != nil {
		fmt.Println("err----", err)
	}
	x, err := gen()
	if err != nil {
		fmt.Println("err##########", err)
	}
	fmt.Println(string(x))
}
