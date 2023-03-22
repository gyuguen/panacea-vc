package panacea_vc

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	"github.com/cosmos/go-bip39"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	didtypes "github.com/medibloc/panacea-core/v2/x/did/types"
	"github.com/medibloc/vc-sdk/pkg/vc"
	"github.com/medibloc/vc-sdk/pkg/vdr"
	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/secp256k1"
)

var (
	validatorMnemonic     = "gather until small bicycle task noise rely soda vault same pig assist hundred drama prize master shrimp express step sand field put ladder off"
	validatorPrivKeyBz, _ = generatePrivateKeyFromMnemonic(validatorMnemonic, 0, 0)
	providerMnemonic      = "jeans canyon muffin scissors trumpet risk snake airport code treat primary popular output sort noble rough gap beef explain blur gloom sudden wish mechanic"
	providerPrivKeyBz, _  = generatePrivateKeyFromMnemonic(providerMnemonic, 0, 0)

	grpcCLI, _ = NewGRPCClient("tcp://13.209.192.170:9090", "panacea-3")
	txBuilder  = NewTxBuilder(grpcCLI)

	required      = presexch.Required
	intFilterType = "integer"
	strFilterType = "string"
)

func TestCreateDID(t *testing.T) {
	txBytes, err := createMsgCreateDIDTxBytes(t, validatorPrivKeyBz)
	require.NoError(t, err)
	resp, err := grpcCLI.BroadcastTx(txBytes)
	require.NoError(t, err)
	fmt.Println(resp.TxResponse)
	require.Equal(t, uint32(0), resp.TxResponse.Code)

	txBytes, err = createMsgCreateDIDTxBytes(t, providerPrivKeyBz)
	require.NoError(t, err)
	resp, err = grpcCLI.BroadcastTx(txBytes)
	require.NoError(t, err)
	fmt.Println(resp.TxResponse)
	require.Equal(t, uint32(0), resp.TxResponse.Code)
}

func TestUpdateDID(t *testing.T) {
	txBytes, err := createUpdateDIDTxBytes(t, validatorPrivKeyBz)
	require.NoError(t, err)
	resp, err := grpcCLI.BroadcastTx(txBytes)
	require.NoError(t, err)
	fmt.Println(resp.TxResponse)
	require.Equal(t, uint32(0), resp.TxResponse.Code)

	txBytes, err = createUpdateDIDTxBytes(t, providerPrivKeyBz)
	require.NoError(t, err)
	resp, err = grpcCLI.BroadcastTx(txBytes)
	require.NoError(t, err)
	fmt.Println(resp.TxResponse)
	require.Equal(t, uint32(0), resp.TxResponse.Code)
}

func TestCreateVCAndVP(t *testing.T) {
	frame, err := vc.NewFramework(vdr.NewPanaceaVDR(grpcCLI))
	require.NoError(t, err)

	issuerDID := newDID(validatorPrivKeyBz)
	holderDID := newDID(providerPrivKeyBz)

	credential := createCredential(issuerDID, holderDID)

	credentialBz, err := credential.MarshalJSON()
	require.NoError(t, err)

	verifiableCredential, err := frame.SignCredential(credentialBz, validatorPrivKeyBz, &vc.ProofOptions{
		VerificationMethod: didtypes.NewVerificationMethodID(newDID(validatorPrivKeyBz), "key1"),
		SignatureType:      vc.EcdsaSecp256k1Signature2019,
	})
	require.NoError(t, err)

	err = frame.VerifyCredential(verifiableCredential)
	require.NoError(t, err)

	// Test VP
	presentation := verifiable.Presentation{
		Context: []string{verifiable.ContextURI},
		ID:      uuid.NewString(),
		Type:    []string{verifiable.VPType},
		Holder:  newDID(providerPrivKeyBz),
	}

	presentationBz, err := presentation.MarshalJSON()
	require.NoError(t, err)
	verifiablePresentationBytes, err := frame.SignPresentation(presentationBz, providerPrivKeyBz, &vc.ProofOptions{
		VerificationMethod: didtypes.NewVerificationMethodID(newDID(providerPrivKeyBz), "key1"),
		SignatureType:      "EcdsaSecp256k1Signature2019",
		Domain:             "https://vc.com",
		Challenge:          "My challenge",
		Created:            time.Now().Format(time.RFC3339),
	})
	require.NoError(t, err)
	_, err = frame.VerifyPresentation(verifiablePresentationBytes)
	require.NoError(t, err)

	// Test VP with PD
	bbsPrivKey, err := bbs12381g2pub.UnmarshalPrivateKey(providerPrivKeyBz)
	require.NoError(t, err)
	bbsPrivKeyBz, err := bbsPrivKey.Marshal()
	require.NoError(t, err)

	pd := &presexch.PresentationDefinition{
		ID:      "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		Purpose: "To sell you a drink we need to know that you are an adult.",
		InputDescriptors: []*presexch.InputDescriptor{{
			ID:      "age_descriptor",
			Purpose: "Your age should be greater or equal to 18.",
			// required temporarily in v0.1.8 for schema verification.
			// schema will be optional by supporting presentation exchange v2
			// https://github.com/hyperledger/aries-framework-go/commit/66d9bf30de2f5cd6116adaac27f277b45077f26f
			Schema: []*presexch.Schema{{
				URI:      "https://www.w3.org/2018/credentials#VerifiableCredential",
				Required: false,
			}, {
				URI:      "https://w3id.org/security/bbs/v1",
				Required: false,
			}},
			Constraints: &presexch.Constraints{
				LimitDisclosure: &required,
				Fields: []*presexch.Field{
					{
						Path: []string{"$.credentialSubject.age"},
						Filter: &presexch.Filter{
							Type:    &intFilterType,
							Minimum: 18,
							Maximum: 30,
						},
					},
					{
						Path: []string{"$.credentialSubject.nationality"},
						Filter: &presexch.Filter{
							Type: &strFilterType,
							Enum: []presexch.StrOrInt{"Korea"},
						},
					},
				},
			},
		}},
	}
	pdBz, err := json.Marshal(pd)
	require.NoError(t, err)

	presentationWithPd, err := frame.CreatePresentationFromPD(credentialBz, pdBz)
	require.NoError(t, err)
	presentationWithPd.Context = append(presentationWithPd.Context, "https://w3id.org/security/bbs/v1")
	presentationWithpdBz, err := presentationWithPd.MarshalJSON()
	require.NoError(t, err)

	verifiablePresentationWithPd, err := frame.SignPresentation(presentationWithpdBz, bbsPrivKeyBz, &vc.ProofOptions{
		VerificationMethod: didtypes.NewVerificationMethodID(newDID(providerPrivKeyBz), "key2"),
		SignatureType:      "BbsBlsSignature2020",
		Domain:             "https://aaa.com",
		Challenge:          "Challenger!",
		Created:            time.Now().Format(time.RFC3339),
	})

	require.NoError(t, err)
	fmt.Println(string(verifiablePresentationWithPd))
}

func createMsgCreateDIDTxBytes(t *testing.T, privKeyBz []byte) ([]byte, error) {
	privKey := secp256k1.PrivKey(privKeyBz)
	blsPrivKey, err := bbs12381g2pub.UnmarshalPrivateKey(privKeyBz)
	require.NoError(t, err)
	blsPubKeyBz, err := blsPrivKey.PublicKey().Marshal()
	require.NoError(t, err)

	did := newDID(privKey)

	verificationMethod := didtypes.NewVerificationMethod(didtypes.NewVerificationMethodID(did, "key1"), didtypes.ES256K_2019, did, privKey.PubKey().Bytes())
	verificationMethod2 := didtypes.NewVerificationMethod(didtypes.NewVerificationMethodID(did, "key2"), didtypes.BLS1281G2_2020, did, blsPubKeyBz)
	verificationMethods := []*didtypes.VerificationMethod{
		&verificationMethod,
		&verificationMethod2,
	}
	authentications := []didtypes.VerificationRelationship{
		didtypes.NewVerificationRelationship(verificationMethod.Id),
		didtypes.NewVerificationRelationship(verificationMethod2.Id),
	}

	doc := didtypes.NewDIDDocument(did, didtypes.WithVerificationMethods(verificationMethods), didtypes.WithAuthentications(authentications))

	sig, err := didtypes.Sign(&doc, didtypes.InitialSequence, privKey)
	require.NoError(t, err)

	msg := didtypes.NewMsgCreateDID(did, doc, verificationMethod.Id, sig, getAddress(privKey.PubKey()))

	return txBuilder.GenerateTxBytes(privKey, &msg)
}

func createUpdateDIDTxBytes(t *testing.T, privKeyBz []byte) ([]byte, error) {
	privKey := secp256k1.PrivKey(privKeyBz)
	blsPrivKey, err := bbs12381g2pub.UnmarshalPrivateKey(privKeyBz)
	require.NoError(t, err)
	blsPubKeyBz, err := blsPrivKey.PublicKey().Marshal()
	require.NoError(t, err)

	did := newDID(privKey)

	didWithSeq, err := grpcCLI.GetDID(context.Background(), did)
	require.NoError(t, err)

	verificationMethod := didtypes.NewVerificationMethod(didtypes.NewVerificationMethodID(did, "key1"), didtypes.ES256K_2019, did, privKey.PubKey().Bytes())
	verificationMethod2 := didtypes.NewVerificationMethod(didtypes.NewVerificationMethodID(did, "key2"), didtypes.BLS1281G2_2020, did, blsPubKeyBz)
	verificationMethods := []*didtypes.VerificationMethod{
		&verificationMethod,
		&verificationMethod2,
	}
	authentications := []didtypes.VerificationRelationship{
		didtypes.NewVerificationRelationship(verificationMethod.Id),
		didtypes.NewVerificationRelationship(verificationMethod2.Id),
	}

	doc := didtypes.NewDIDDocument(did, didtypes.WithVerificationMethods(verificationMethods), didtypes.WithAuthentications(authentications))

	sig, err := didtypes.Sign(&doc, didWithSeq.Sequence, privKey)
	if err != nil {
		panic(err)
	}

	msg := didtypes.NewMsgUpdateDID(did, doc, verificationMethod.Id, sig, getAddress(privKey.PubKey()))
	return txBuilder.GenerateTxBytes(privKey, &msg)
}

func generatePrivateKeyFromMnemonic(mnemonic string, accNum, index uint32) ([]byte, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic")
	}

	hdPath := hd.NewFundraiserParams(accNum, 371, index).String()
	master, ch := hd.ComputeMastersFromSeed(bip39.NewSeed(mnemonic, ""))

	return hd.DerivePrivateKeyForPath(master, ch, hdPath)
}

func getAddress(pubKey crypto.PubKey) string {
	addr, err := bech32.ConvertAndEncode("panacea", pubKey.Address().Bytes())
	if err != nil {
		panic(err)
	}
	return addr
}

func newDID(privKey []byte) string {
	return didtypes.NewDID(secp256k1.PrivKey(privKey).PubKey().Bytes())
}

func createCredential(issuerDID, holderDID string) verifiable.Credential {
	return verifiable.Credential{
		ID:      uuid.NewString(),
		Context: []string{verifiable.ContextURI, "https://w3id.org/security/bbs/v1"},
		Types:   []string{verifiable.VCType},
		Issuer: verifiable.Issuer{
			ID: issuerDID,
		},
		Issued: &util.TimeWrapper{
			Time: time.Now(),
		},
		Subject: map[string]interface{}{
			"id":          holderDID,
			"first_name":  "Gildong",
			"last_name":   "Hong",
			"age":         21,
			"nationality": "Korea",
			"hobby":       "movie",
		},
	}
}
