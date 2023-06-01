package main

import (
	"crypto/ecdsa"
	_ "embed"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"code.vegaprotocol.io/vega/core/bridges"
	"code.vegaprotocol.io/vega/core/config"
	"code.vegaprotocol.io/vega/core/nodewallets"
	"code.vegaprotocol.io/vega/libs/num"
	"code.vegaprotocol.io/vega/paths"
	v2 "code.vegaprotocol.io/vega/protos/data-node/api/v2"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	bridgeAddress = "0x23872549cE10B40e31D6577e0A920088B0E0666a"
)

var (
	//go:embed mainnet10.json
	buf10 []byte
	//go:embed mainnet11.json
	buf11 []byte

	vegaHome      string
	privateKey    string
	outfile       string
	reconcile     bool
	signaturesDir string
)

func init() {
	flag.StringVar(&vegaHome, "home", "", "path to custom vega home")
	flag.StringVar(&privateKey, "privkey", "", "a ethereum private key to be use to sign the messages")
	flag.StringVar(&outfile, "outfile", "out.csv", "a path to a file to save the output")
	flag.BoolVar(&reconcile, "reconcile", false, "reconcile files")
	flag.StringVar(&signaturesDir, "sigdir", "signatures", "folder contaning all signatures")
}

func main() {
	flag.Parse()

	if len(outfile) <= 0 {
		log.Fatal("outfile argument is required")
	}

	if reconcile {
		if len(signaturesDir) <= 0 {
			log.Fatal("sigdir argument required")
		}

		doReconcile()
		return
	}

	switch {
	case len(vegaHome) > 0:
		log.Printf("using vega home: %v", vegaHome)
	case len(privateKey) <= 0:
		log.Printf("using default vega home")
	default:
		log.Printf("uisng private key: %v", privateKey)
	}

	vegaPaths := paths.New(vegaHome)
	s, err := getSigner(vegaPaths)
	if err != nil {
		log.Panicf("couldn't load node signer: %v", err)
	}

	erc20Logic := bridges.NewERC20Logic(s, bridgeAddress)

	ws := extractAllStranded()

	var l int
	for _, v := range ws {
		l += len(v)
	}

	fmt.Printf("total amount of withdrawals stranded: %v\n", l)

	bar := progressbar.Default(int64(l))

	out := "party, withdrawalId, signature\n"
	for k, v := range ws {
		for _, w := range v {
			amount, _ := num.UintFromString(w.Amount, 10)
			nonce, _ := num.UintFromString(w.Nonce, 10)
			signature, err := erc20Logic.WithdrawAsset(
				w.AssetSource, amount, w.TargetAddress, time.Unix(w.Creation, 0), nonce,
			)
			if err != nil {
				log.Panicf("error building signature: %v", err)
			}

			// fmt.Printf("%v - %v - %v - %v - %v - %v - 0x%v\n", w.AssetSource, w.Amount, w.TargetAddress, bridgeAddress, w.Creation, w.Nonce, signature.Signature.Hex())
			out = fmt.Sprintf("%v%v,%v,0x%v\n", out, k, w.WithdrawalID, signature.Signature.Hex())

			bar.Add(1)
		}
	}

	err = ioutil.WriteFile(outfile, []byte(out), 0644)
	if err != nil {
		log.Fatalf("could not marshal data: %v", err)
	}
}

func extractAllStranded() map[string][]idBundlePair {
	ws := getStrandedWithdrawals(buf10)
	for k, v := range getStrandedWithdrawals(buf11) {
		w, ok := ws[k]
		if !ok {
			w = []idBundlePair{}
		}

		ws[k] = append(w, v...)
	}

	return ws
}

func doReconcile() {
	ws := extractAllStranded()

	// first clear up old signatures
	for _, v := range ws {
		for _, w := range v {
			w.Signatures = "0x"
		}
	}

	fileSystem := os.DirFS(signaturesDir)

	fs.WalkDir(fileSystem, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Fatal(err)
		}
		if !d.IsDir() {
			signatures := getNewSignatures(filepath.Join(signaturesDir, path))

			// now add the signatures in there
			for _, v := range signatures {
				for _, w := range ws[v.Party] {
					if w.WithdrawalID == v.WithdrawID {
						w.Signatures += v.Signature
						break
					}
				}
			}

		}
		return nil
	})

	// now write the final output
	// fmt.Printf("%v - %v - %v - %v - %v - %v - 0x%v\n", w.AssetSource, w.Amount, w.TargetAddress, bridgeAddress, w.Creation, w.Nonce, signature.Signature.Hex())
	out := "party, withdrawalId, assetSource, amount, targetAddress, creation, nonce, signatures\n"
	for k, v := range ws {
		for _, w := range v {
			out = fmt.Sprintf("%v%v,%v,%v,%v,%v,%v,%v,%v\n", out, k, w.WithdrawalID, w.AssetSource, w.Amount, w.TargetAddress, w.Creation, w.Nonce, w.Signatures)
		}
	}

	err := ioutil.WriteFile(outfile, []byte(out), 0644)
	if err != nil {
		log.Fatalf("could write file: %v", err)
	}
}

type newSignature struct {
	Party      string
	WithdrawID string
	Signature  string
}

func getNewSignatures(filePath string) []newSignature {
	signatures := []newSignature{}
	buf, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("couldn't read file: %v", err)
	}

	r := csv.NewReader(strings.NewReader(string(buf)))

	records, err := r.ReadAll()
	if err != nil {
		log.Fatal(err)
	}

	for _, v := range records[1:] {
		signatures = append(signatures, newSignature{v[0], v[1], v[2][2:]})
	}

	return signatures
}

func getSigner(vegaPaths paths.Paths) (bridges.Signer, error) {
	_, _, err := config.EnsureNodeConfig(vegaPaths)
	if err != nil {
		return nil, err
	}

	var s bridges.Signer
	if len(privateKey) <= 0 {
		passphrase, err := promptForPassphrase("Enter node wallet passphrase:")
		if err != nil {
			return nil, err
		}

		s, err = nodewallets.GetEthereumWallet(vegaPaths, passphrase)
		if err != nil {
			return nil, fmt.Errorf("couldn't get Ethereum node wallet: %w", err)
		}
	} else {
		s, err = NewPrivKeySigner(privateKey)
		if err != nil {
			return nil, fmt.Errorf("couldn't load private key: %w", err)
		}
	}

	return s, nil
}

func promptForPassphrase(msg string) (string, error) {
	fmt.Print(msg)
	password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", fmt.Errorf("failed to read passphrase input: %w", err)
	}
	fmt.Println()

	return string(password), nil
}

type PrivKeySigner struct {
	privateKey *ecdsa.PrivateKey
}

func NewPrivKeySigner(hexPrivKey string) (*PrivKeySigner, error) {
	privateKey, err := crypto.HexToECDSA(hexPrivKey)
	if err != nil {
		return nil, err
	}

	return &PrivKeySigner{
		privateKey: privateKey,
	}, nil
}

func (p *PrivKeySigner) Sign(hash []byte) ([]byte, error) {
	return crypto.Sign(hash, p.privateKey)
}

func (p *PrivKeySigner) Algo() string {
	return ""
}

type Withdrawal struct {
	Withdrawal struct {
		Amount string `json:"amount"`
		Id     string `json:"id"`
		TxHash string `json:"tx_hash"`
		Status int    `json:"status"`
		Ext    struct {
			Ext struct {
				ERC20 struct {
					ReceiverAddress string `json:"receiver_address"`
				} `json:"Erc20"`
			} `json:"Ext"`
		} `json:"ext"`
	} `json:"withdrawal"`
	Bundle *v2.GetERC20WithdrawalApprovalResponse `json:"bundle,omitempty"`
}

type entry struct {
	Party       string       `json:"party"`
	Withdrawals []Withdrawal `json:"withdrawal"`
}

type idBundlePair struct {
	WithdrawalID string
	*v2.GetERC20WithdrawalApprovalResponse
}

func getStrandedWithdrawals(buf []byte) map[string][]idBundlePair { // map of party to withdrawls bundles
	store := []entry{}

	err := json.Unmarshal(buf, &store)
	if err != nil {
		log.Fatalf("could not unmarshal: %v", err)
	}

	out := map[string][]idBundlePair{}
	for _, v := range store {
		for _, w := range v.Withdrawals {
			if w.Withdrawal.Status == 3 && len(w.Withdrawal.TxHash) <= 0 {
				entry, ok := out[v.Party]
				if !ok {
					entry = []idBundlePair{}
				}

				out[v.Party] = append(entry, idBundlePair{w.Withdrawal.Id, w.Bundle})

			}
		}
	}

	return out
}
