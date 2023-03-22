package panacea_vc

import (
	"fmt"

	clienttx "github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"
)

type TxBuilder struct {
	client GRPCClient
}

func NewTxBuilder(client GRPCClient) *TxBuilder {
	return &TxBuilder{
		client: client,
	}
}

// GenerateTxBytes generates transaction byte array.
func (tb TxBuilder) GenerateTxBytes(privKeyBz []byte, msg ...sdk.Msg) ([]byte, error) {
	txBytes, err := tb.GenerateSignedTxBytes(privKeyBz, 200000, sdk.NewCoins(sdk.NewCoin("umed", sdk.NewInt(1000000))), msg...)
	if err != nil {
		return nil, err
	}

	return txBytes, nil
}

// GenerateSignedTxBytes signs msgs using the private key and returns the signed Tx message in form of byte array.
func (tb TxBuilder) GenerateSignedTxBytes(
	privKeyBz []byte,
	gasLimit uint64,
	feeAmount sdk.Coins,
	msg ...sdk.Msg,
) ([]byte, error) {
	privateKey := &secp256k1.PrivKey{
		Key: privKeyBz,
	}

	txConfig := authtx.NewTxConfig(tb.client.GetCdc(), []signing.SignMode{signing.SignMode_SIGN_MODE_DIRECT})
	txBuilder := txConfig.NewTxBuilder()
	txBuilder.SetGasLimit(gasLimit)
	txBuilder.SetFeeAmount(feeAmount)

	if err := txBuilder.SetMsgs(msg...); err != nil {
		return nil, err
	}

	signerAddress, err := bech32.ConvertAndEncode("panacea", privateKey.PubKey().Address().Bytes())
	if err != nil {
		return nil, err
	}

	signerAccount, err := tb.client.GetAccount(signerAddress)
	if err != nil {
		return nil, fmt.Errorf("can not get signer account from address(%s): %w", signerAddress, err)
	}

	sigV2 := signing.SignatureV2{
		PubKey: privateKey.PubKey(),
		Data: &signing.SingleSignatureData{
			SignMode:  signing.SignMode_SIGN_MODE_DIRECT,
			Signature: nil,
		},
		Sequence: signerAccount.GetSequence(),
	}

	if err := txBuilder.SetSignatures(sigV2); err != nil {
		return nil, err
	}

	signerData := authsigning.SignerData{
		ChainID:       tb.client.GetChainID(),
		AccountNumber: signerAccount.GetAccountNumber(),
		Sequence:      signerAccount.GetSequence(),
	}

	sigV2, err = clienttx.SignWithPrivKey(
		signing.SignMode_SIGN_MODE_DIRECT,
		signerData,
		txBuilder,
		privateKey,
		txConfig,
		signerAccount.GetSequence(),
	)
	if err != nil {
		return nil, err
	}

	if err := txBuilder.SetSignatures(sigV2); err != nil {
		return nil, err
	}

	return txConfig.TxEncoder()(txBuilder.GetTx())
}
