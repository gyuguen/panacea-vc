package panacea_vc

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/url"
	"time"

	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/std"
	"github.com/cosmos/cosmos-sdk/types/tx"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	didtypes "github.com/medibloc/panacea-core/v2/x/did/types"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type GRPCClient interface {
	Close() error
	BroadcastTx(txBytes []byte) (*tx.BroadcastTxResponse, error)
	GetCdc() *codec.ProtoCodec
	GetChainID() string
	GetAccount(address string) (authtypes.AccountI, error)
	GetDID(context.Context, string) (*didtypes.DIDDocumentWithSeq, error)
}

var _ GRPCClient = &grpcClient{}

type grpcClient struct {
	conn    *grpc.ClientConn
	cdc     *codec.ProtoCodec
	chainID string
}

func NewGRPCClient(grpcAddr, chainID string) (GRPCClient, error) {
	log.Infof("dialing to Panacea gRPC endpoint: %s", grpcAddr)

	parsedUrl, err := url.Parse(grpcAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse gRPC endpoint. please use absolute URL (scheme://host:port): %w", err)
	}

	var cred grpc.DialOption

	if parsedUrl.Scheme == "https" {
		cred = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{}))
	} else {
		cred = grpc.WithInsecure()
	}

	conn, err := grpc.Dial(parsedUrl.Host, cred)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Panacea: %w", err)
	}

	return &grpcClient{
		conn:    conn,
		cdc:     codec.NewProtoCodec(makeInterfaceRegistry()),
		chainID: chainID,
	}, nil
}

func (c *grpcClient) Close() error {
	log.Info("closing Panacea gRPC connection")
	return c.conn.Close()
}

func (c *grpcClient) BroadcastTx(txBytes []byte) (*tx.BroadcastTxResponse, error) {
	txClient := tx.NewServiceClient(c.conn)

	return txClient.BroadcastTx(
		context.Background(),
		&tx.BroadcastTxRequest{
			Mode:    tx.BroadcastMode_BROADCAST_MODE_BLOCK,
			TxBytes: txBytes,
		},
	)
}

func (c *grpcClient) GetCdc() *codec.ProtoCodec {
	return c.cdc
}

func (c *grpcClient) GetChainID() string {
	return c.chainID
}

func (c *grpcClient) GetDID(ctx context.Context, did string) (*didtypes.DIDDocumentWithSeq, error) {
	cli := didtypes.NewQueryClient(c.conn)

	res, err := cli.DID(ctx, &didtypes.QueryDIDRequest{
		DidBase64: base64.StdEncoding.EncodeToString([]byte(did)),
	})

	if err != nil {
		return nil, err
	}

	return res.DidDocumentWithSeq, nil
}

func (c *grpcClient) GetAccount(address string) (authtypes.AccountI, error) {
	client := authtypes.NewQueryClient(c.conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	response, err := client.Account(ctx, &authtypes.QueryAccountRequest{Address: address})
	if err != nil {
		return nil, fmt.Errorf("failed to get account info via grpc: %w", err)
	}

	var acc authtypes.AccountI
	if err := c.cdc.UnpackAny(response.GetAccount(), &acc); err != nil {
		return nil, fmt.Errorf("failed to unpack account info: %w", err)
	}
	return acc, nil
}

func makeInterfaceRegistry() sdk.InterfaceRegistry {
	interfaceRegistry := sdk.NewInterfaceRegistry()
	std.RegisterInterfaces(interfaceRegistry)
	authtypes.RegisterInterfaces(interfaceRegistry)
	return interfaceRegistry
}
