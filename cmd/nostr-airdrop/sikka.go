package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"golang.org/x/crypto/sha3"
)

const (
	subunitsPerSikka = int64(10_000_000_000)
	addressHRP       = "sikka"
	addressVersion   = byte(1)
	bech32mConstant  = uint32(0x2bc830a3)
	bech32Charset    = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	signingDomain    = "sikka:v2:txinput"
	nodeHTTPTimeout  = 10 * time.Second
	nodeMaxAttempts  = 3
	nodeRetryDelay   = 500 * time.Millisecond
)

var mldsaScheme = mldsa87.Scheme()
var nodeHTTPClient = &http.Client{Timeout: nodeHTTPTimeout}

type Wallet struct {
	SKBytes []byte
	PKHex   string
	Address string
}

type TxInput struct {
	TxID    string     `json:"txid"`
	Index   int        `json:"index"`
	Witness *TxWitness `json:"witness,omitempty"`
}

type TxWitness struct {
	Type      string            `json:"type"`
	Threshold *ThresholdWitness `json:"threshold,omitempty"`
}

type ThresholdWitness struct {
	Threshold  int      `json:"threshold"`
	PublicKeys []string `json:"public_keys"`
	Signatures []string `json:"signatures"`
}

type TxOutput struct {
	Address string `json:"address"`
	Value   int64  `json:"value"`
}

type Transaction struct {
	ID        string     `json:"id,omitempty"`
	Parents   []string   `json:"parents"`
	Inputs    []TxInput  `json:"inputs"`
	Outputs   []TxOutput `json:"outputs"`
	PowNonce  int64      `json:"pow_nonce"`
	PowBits   int        `json:"pow_bits"`
	Timestamp int64      `json:"timestamp"`
}

type UTXO struct {
	TxID     string `json:"txid"`
	Index    int    `json:"index"`
	Address  string `json:"address"`
	Value    int64  `json:"value"`
	DAGDepth int64  `json:"dag_depth"`
}

type AddressInfo struct {
	Address   string `json:"address"`
	Balance   int64  `json:"balance"`
	UTXOCount int    `json:"utxo_count"`
	UTXOs     []UTXO `json:"utxos"`
}

type PowQuoteRequest struct {
	Parents   []string `json:"parents"`
	Timestamp int64    `json:"timestamp"`
}

type PowQuoteResponse struct {
	RequiredBits int `json:"required_bits"`
}

type SubmitResponse struct {
	TxID   string `json:"txid"`
	Status string `json:"status"`
}

type NodeStatus struct {
	Tips    []string `json:"tips"`
	DAGSize int64
}

func decodeBech32m(address string) (hrp string, version byte, program []byte, err error) {
	sep := strings.LastIndexByte(address, '1')
	if sep < 1 || sep+7 > len(address) {
		return "", 0, nil, fmt.Errorf("invalid bech32m length")
	}
	hr := address[:sep]
	encoded := address[sep+1:]
	values := make([]byte, len(encoded))
	for i := range encoded {
		idx := strings.IndexByte(bech32Charset, encoded[i])
		if idx < 0 {
			return "", 0, nil, fmt.Errorf("invalid bech32m character %q", encoded[i])
		}
		values[i] = byte(idx)
	}
	if !bech32VerifyChecksum(hr, values) {
		return "", 0, nil, fmt.Errorf("invalid bech32m checksum")
	}
	values = values[:len(values)-6]
	if len(values) == 0 {
		return "", 0, nil, fmt.Errorf("address payload empty")
	}
	prog, err := convertBits(values[1:], 5, 8, false)
	if err != nil {
		return "", 0, nil, err
	}
	return hr, values[0], prog, nil
}

func encodeBech32m(hrp string, version byte, program []byte) (string, error) {
	converted, err := convertBits(program, 8, 5, true)
	if err != nil {
		return "", err
	}
	data := append([]byte{version}, converted...)
	checksum := bech32Checksum(hrp, data)
	combined := append(data, checksum...)
	var out strings.Builder
	out.WriteString(hrp)
	out.WriteByte('1')
	for _, v := range combined {
		out.WriteByte(bech32Charset[v])
	}
	return out.String(), nil
}

func validateAddress(addr string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(addr))
	hr, ver, prog, err := decodeBech32m(normalized)
	if err != nil {
		return "", err
	}
	if hr != addressHRP {
		return "", fmt.Errorf("wrong address HRP: %s", hr)
	}
	if ver != addressVersion {
		return "", fmt.Errorf("wrong address version: %d", ver)
	}
	if len(prog) != 32 {
		return "", fmt.Errorf("wrong program length: %d", len(prog))
	}
	return normalized, nil
}

func publicKeyToAddress(pkHex string) (string, error) {
	descriptor := fmt.Sprintf("mldsa87:1:[%s]", pkHex)
	payload := sha3.Sum256(append([]byte{addressVersion}, []byte(descriptor)...))
	return encodeBech32m(addressHRP, addressVersion, payload[:])
}

func convertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	acc, bits := 0, uint(0)
	maxVal := (1 << toBits) - 1
	maxAcc := (1 << (fromBits + toBits - 1)) - 1
	var out []byte
	for _, v := range data {
		if v>>fromBits != 0 {
			return nil, fmt.Errorf("invalid data range")
		}
		acc = ((acc << fromBits) | int(v)) & maxAcc
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			out = append(out, byte((acc>>bits)&maxVal))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte((acc<<(toBits-bits))&maxVal))
		}
	} else if bits >= fromBits || ((acc<<(toBits-bits))&maxVal) != 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	return out, nil
}

func bech32Checksum(hrp string, data []byte) []byte {
	vals := append(bech32HRPExpand(hrp), data...)
	vals = append(vals, 0, 0, 0, 0, 0, 0)
	pm := bech32Polymod(vals) ^ bech32mConstant
	cs := make([]byte, 6)
	for i := range cs {
		cs[i] = byte((pm >> (5 * (5 - i))) & 31)
	}
	return cs
}

func bech32VerifyChecksum(hrp string, values []byte) bool {
	return bech32Polymod(append(bech32HRPExpand(hrp), values...)) == bech32mConstant
}

func bech32HRPExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := range hrp {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := range hrp {
		out = append(out, hrp[i]&31)
	}
	return out
}

func bech32Polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = ((chk & 0x1ffffff) << 5) ^ uint32(v)
		if top&1 != 0 {
			chk ^= 0x3b6a57b2
		}
		if top&2 != 0 {
			chk ^= 0x26508e6d
		}
		if top&4 != 0 {
			chk ^= 0x1ea119fa
		}
		if top&8 != 0 {
			chk ^= 0x3d4233dd
		}
		if top&16 != 0 {
			chk ^= 0x2a1462b3
		}
	}
	return chk
}

func computeTxIDRaw(tx *Transaction) [32]byte {
	var buf []byte
	buf = append(buf, 0x02)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(tx.Parents)))
	for _, parent := range tx.Parents {
		buf = append(buf, decodeHash32(parent)...)
	}
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(tx.Inputs)))
	for _, in := range tx.Inputs {
		buf = append(buf, decodeHash32(in.TxID)...)
		buf = binary.BigEndian.AppendUint32(buf, uint32(in.Index))
	}
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(tx.Outputs)))
	for _, out := range tx.Outputs {
		ab := []byte(out.Address)
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(ab)))
		buf = append(buf, ab...)
		buf = binary.BigEndian.AppendUint64(buf, uint64(out.Value))
	}
	buf = binary.BigEndian.AppendUint64(buf, uint64(tx.Timestamp))
	return sha3.Sum256(buf)
}

func signingPayload(tx *Transaction, inputIndex int, utxo *UTXO) []byte {
	txID := computeTxIDRaw(tx)
	addrBytes := []byte(utxo.Address)
	spentTxID := decodeHash32(utxo.TxID)
	var buf []byte
	buf = append(buf, []byte(signingDomain)...)
	buf = append(buf, txID[:]...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(inputIndex))
	buf = append(buf, spentTxID...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(utxo.Index))
	buf = binary.BigEndian.AppendUint64(buf, uint64(utxo.Value))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(addrBytes)))
	buf = append(buf, addrBytes...)
	return buf
}

func minePoW(tx *Transaction, minBits int) error {
	for nonce := int64(0); ; nonce++ {
		tx.PowNonce = nonce
		txID := computeTxIDRaw(tx)
		var buf [40]byte
		copy(buf[:32], txID[:])
		binary.BigEndian.PutUint64(buf[32:], uint64(nonce))
		hash := sha3.Sum256(buf[:])
		if leadingZeroBits(hash[:]) >= minBits {
			tx.PowBits = leadingZeroBits(hash[:])
			return nil
		}
	}
}

func leadingZeroBits(data []byte) int {
	count := 0
	for _, byt := range data {
		if byt == 0 {
			count += 8
			continue
		}
		for bit := 7; bit >= 0; bit-- {
			if byt&(1<<uint(bit)) != 0 {
				return count
			}
			count++
		}
		break
	}
	return count
}

func decodeHash32(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 {
		return make([]byte, 32)
	}
	return b
}

func walletFromSeed(seed []byte) (*Wallet, error) {
	if len(seed) != mldsa87.SeedSize {
		return nil, fmt.Errorf("wallet seed must be %d bytes", mldsa87.SeedSize)
	}
	skBytes, pkHex, address, err := loadPrivateKey(hex.EncodeToString(seed))
	if err != nil {
		return nil, err
	}
	return &Wallet{SKBytes: skBytes, PKHex: pkHex, Address: address}, nil
}

func deriveServiceWallet(root []byte) (*Wallet, error) {
	seed := sha3.Sum256(append(append([]byte{}, root...), []byte("service-wallet")...))
	return walletFromSeed(seed[:])
}

func deriveUserWallet(root []byte, userPubKey string) (*Wallet, error) {
	seedMaterial := append(append([]byte{}, root...), []byte(strings.ToLower(strings.TrimSpace(userPubKey)))...)
	seed := sha3.Sum256(seedMaterial)
	return walletFromSeed(seed[:])
}

func loadPrivateKey(privKeyHex string) (skBytes []byte, pkHex string, addr string, err error) {
	raw, err := hex.DecodeString(strings.TrimSpace(privKeyHex))
	if err != nil {
		return nil, "", "", fmt.Errorf("decode private key hex: %w", err)
	}

	var sk mldsa87.PrivateKey
	var pk mldsa87.PublicKey

	if len(raw) == mldsa87.SeedSize {
		var seed [mldsa87.SeedSize]byte
		copy(seed[:], raw)
		pubKey, privKey := mldsa87.NewKeyFromSeed(&seed)
		pk = *pubKey
		sk = *privKey
	} else {
		privKey, err2 := mldsaScheme.UnmarshalBinaryPrivateKey(raw)
		if err2 != nil {
			return nil, "", "", fmt.Errorf("unmarshal private key: %w", err2)
		}
		pubKey, ok := privKey.Public().(mldsa87.PublicKey)
		if !ok {
			return nil, "", "", fmt.Errorf("unexpected public key type")
		}
		sk = *(privKey.(*mldsa87.PrivateKey))
		pk = pubKey
	}

	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, "", "", fmt.Errorf("marshal public key: %w", err)
	}
	pkHex = strings.ToLower(hex.EncodeToString(pkBytes))

	addr, err = publicKeyToAddress(pkHex)
	if err != nil {
		return nil, "", "", fmt.Errorf("derive address: %w", err)
	}

	skBytes, err = sk.MarshalBinary()
	if err != nil {
		return nil, "", "", fmt.Errorf("marshal private key: %w", err)
	}

	return skBytes, pkHex, addr, nil
}

func signInput(skBytes []byte, payload []byte) (string, error) {
	sk, err := mldsaScheme.UnmarshalBinaryPrivateKey(skBytes)
	if err != nil {
		return "", fmt.Errorf("unmarshal sk: %w", err)
	}
	sig := mldsaScheme.Sign(sk, payload, nil)
	return strings.ToLower(hex.EncodeToString(sig)), nil
}

func doNodeRequest(method, url string, body []byte) (*http.Response, error) {
	var lastErr error

	for attempt := 1; attempt <= nodeMaxAttempts; attempt++ {
		var reqBody io.Reader
		if body != nil {
			reqBody = bytes.NewReader(body)
		}

		req, err := http.NewRequest(method, url, reqBody)
		if err != nil {
			return nil, fmt.Errorf("build %s request: %w", method, err)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := nodeHTTPClient.Do(req)
		if err == nil {
			if resp.StatusCode < http.StatusInternalServerError || attempt == nodeMaxAttempts {
				return resp, nil
			}

			lastErr = fmt.Errorf("status %d", resp.StatusCode)
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		} else {
			lastErr = err
		}

		if attempt < nodeMaxAttempts {
			time.Sleep(time.Duration(attempt) * nodeRetryDelay)
		}
	}

	return nil, fmt.Errorf("%s %s failed after %d attempts: %w", method, url, nodeMaxAttempts, lastErr)
}

func getAddressInfo(nodeURL, address string) (*AddressInfo, error) {
	url := fmt.Sprintf("%s/v1/address/%s", strings.TrimRight(nodeURL, "/"), address)
	resp, err := doNodeRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("GET address: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GET address %d: %s", resp.StatusCode, body)
	}
	var info AddressInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode address info: %w", err)
	}
	if info.UTXOs == nil {
		info.UTXOs = []UTXO{}
	}
	if info.Address != "" && info.Address != address {
		return nil, fmt.Errorf("address response mismatch: requested %s, got %s", address, info.Address)
	}
	if info.UTXOCount != 0 && info.UTXOCount != len(info.UTXOs) {
		return nil, fmt.Errorf("address response mismatch: utxo_count=%d, utxos=%d", info.UTXOCount, len(info.UTXOs))
	}
	return &info, nil
}

func parseNodeURLs(raw string) []string {
	parts := strings.Split(raw, ",")
	nodeURLs := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		nodeURL := strings.TrimSpace(part)
		if nodeURL == "" {
			continue
		}
		if _, ok := seen[nodeURL]; ok {
			continue
		}
		seen[nodeURL] = struct{}{}
		nodeURLs = append(nodeURLs, nodeURL)
	}
	return nodeURLs
}

func parseStatusIntField(fields map[string]json.RawMessage, keys ...string) int64 {
	for _, key := range keys {
		raw, ok := fields[key]
		if !ok {
			continue
		}

		var number int64
		if err := json.Unmarshal(raw, &number); err == nil {
			return number
		}

		var text string
		if err := json.Unmarshal(raw, &text); err == nil {
			parsed, err := strconv.ParseInt(strings.TrimSpace(text), 10, 64)
			if err == nil {
				return parsed
			}
		}
	}

	return 0
}

func getNodeStatus(nodeURL string) (*NodeStatus, error) {
	url := fmt.Sprintf("%s/v1/status", strings.TrimRight(nodeURL, "/"))
	resp, err := doNodeRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("GET status: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GET status %d: %s", resp.StatusCode, body)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read status body: %w", err)
	}

	var status NodeStatus
	if err := json.Unmarshal(body, &status); err != nil {
		return nil, fmt.Errorf("decode status: %w", err)
	}
	if len(status.Tips) < 1 {
		return nil, fmt.Errorf("node status returned no tips")
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, fmt.Errorf("decode status fields: %w", err)
	}
	status.DAGSize = parseStatusIntField(fields,
		"dag_size",
		"dagSize",
		"dag_depth",
		"dagDepth",
		"height",
		"best_height",
		"bestHeight",
	)

	return &status, nil
}

func selectBestNodeURL(nodeURLs []string) (string, error) {
	if len(nodeURLs) == 0 {
		return "", fmt.Errorf("no node URLs configured")
	}

	var selectedURL string
	var selectedDAGSize int64
	var lastErr error

	for _, nodeURL := range nodeURLs {
		status, err := getNodeStatus(nodeURL)
		if err != nil {
			log.Printf("skip sikka node %s: %v", nodeURL, err)
			lastErr = err
			continue
		}

		if selectedURL == "" || status.DAGSize > selectedDAGSize {
			selectedURL = nodeURL
			selectedDAGSize = status.DAGSize
		}
	}

	if selectedURL == "" {
		if lastErr == nil {
			lastErr = fmt.Errorf("no valid node returned status")
		}
		return "", lastErr
	}

	return selectedURL, nil
}

func getTips(nodeURL string) ([]string, error) {
	status, err := getNodeStatus(nodeURL)
	if err != nil {
		return nil, err
	}
	if len(status.Tips) == 1 {
		return []string{status.Tips[0], status.Tips[0]}, nil
	}
	return status.Tips[:2], nil
}

func getPowQuote(nodeURL string, tx *Transaction) (*PowQuoteResponse, error) {
	if tx == nil {
		return nil, fmt.Errorf("transaction is required")
	}
	body, err := json.Marshal(PowQuoteRequest{Parents: tx.Parents, Timestamp: tx.Timestamp})
	if err != nil {
		return nil, fmt.Errorf("marshal pow quote request: %w", err)
	}
	url := fmt.Sprintf("%s/v1/tx/pow-quote", strings.TrimRight(nodeURL, "/"))
	resp, err := doNodeRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, fmt.Errorf("POST pow quote: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("pow quote %d: %s", resp.StatusCode, respBody)
	}
	var quote PowQuoteResponse
	if err := json.NewDecoder(resp.Body).Decode(&quote); err != nil {
		return nil, fmt.Errorf("decode pow quote: %w", err)
	}
	if quote.RequiredBits < 0 {
		return nil, fmt.Errorf("invalid pow quote: required_bits=%d", quote.RequiredBits)
	}
	return &quote, nil
}

func submitTx(nodeURL string, tx *Transaction) (string, error) {
	body, err := json.Marshal(tx)
	if err != nil {
		return "", fmt.Errorf("marshal tx: %w", err)
	}
	url := fmt.Sprintf("%s/v1/tx/submit", strings.TrimRight(nodeURL, "/"))
	resp, err := doNodeRequest(http.MethodPost, url, body)
	if err != nil {
		return "", fmt.Errorf("POST tx: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("submit tx %d: %s", resp.StatusCode, respBody)
	}
	var sr SubmitResponse
	if err := json.Unmarshal(respBody, &sr); err != nil {
		return "", fmt.Errorf("decode submit response: %w", err)
	}
	return sr.TxID, nil
}

func sendExactAmount(nodeURL string, wallet *Wallet, recipientAddr string, amount int64) (string, error) {
	if wallet == nil {
		return "", fmt.Errorf("wallet is required")
	}
	if amount <= 0 {
		return "", fmt.Errorf("amount must be greater than zero")
	}

	info, err := getAddressInfo(nodeURL, wallet.Address)
	if err != nil {
		return "", fmt.Errorf("fetch source balance: %w", err)
	}
	if info.Balance < amount || len(info.UTXOs) == 0 {
		return "", fmt.Errorf("insufficient funds in %s", wallet.Address)
	}

	var selected []UTXO
	var inputTotal int64
	for _, utxo := range info.UTXOs {
		selected = append(selected, utxo)
		inputTotal += utxo.Value
		if inputTotal >= amount {
			break
		}
	}
	if inputTotal < amount {
		return "", fmt.Errorf("insufficient UTXOs to cover amount")
	}

	tips, err := getTips(nodeURL)
	if err != nil {
		return "", fmt.Errorf("select tips: %w", err)
	}

	outputs := []TxOutput{{Address: recipientAddr, Value: amount}}
	change := inputTotal - amount
	if change > 0 {
		outputs = append(outputs, TxOutput{Address: wallet.Address, Value: change})
	}

	inputs := make([]TxInput, len(selected))
	for i, utxo := range selected {
		inputs[i] = TxInput{TxID: utxo.TxID, Index: utxo.Index}
	}

	tx := &Transaction{
		Parents:   tips,
		Inputs:    inputs,
		Outputs:   outputs,
		Timestamp: time.Now().Unix(),
	}

	for i, utxo := range selected {
		payload := signingPayload(tx, i, &utxo)
		sig, err := signInput(wallet.SKBytes, payload)
		if err != nil {
			return "", fmt.Errorf("sign input %d: %w", i, err)
		}
		tx.Inputs[i].Witness = &TxWitness{
			Type: "threshold",
			Threshold: &ThresholdWitness{
				Threshold:  1,
				PublicKeys: []string{wallet.PKHex},
				Signatures: []string{sig},
			},
		}
	}

	quote, err := getPowQuote(nodeURL, tx)
	if err != nil {
		return "", fmt.Errorf("quote PoW: %w", err)
	}
	if err := minePoW(tx, quote.RequiredBits); err != nil {
		return "", fmt.Errorf("mine PoW: %w", err)
	}

	txIDRaw := computeTxIDRaw(tx)
	tx.ID = hex.EncodeToString(txIDRaw[:])

	txID, err := submitTx(nodeURL, tx)
	if err != nil {
		return "", fmt.Errorf("submit tx: %w", err)
	}
	return txID, nil
}

func formatSikka(chillar int64) string {
	whole := chillar / subunitsPerSikka
	frac := chillar % subunitsPerSikka
	if frac < 0 {
		frac = -frac
	}
	return fmt.Sprintf("%d.%010d", whole, frac)
}
