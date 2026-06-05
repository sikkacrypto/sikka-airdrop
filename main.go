package main

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	_ "modernc.org/sqlite"
	"golang.org/x/crypto/sha3"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	subunitsPerSikka = int64(10_000_000_000)
	addressHRP       = "sikka"
	addressVersion   = byte(1)
	bech32mConstant  = uint32(0x2bc830a3)
	bech32Charset    = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	signingDomain    = "sikka:v2:txinput"
	claimCooldown    = 2 * time.Hour
	airdropDivisor   = int64(1_000_000)
	nodeHTTPTimeout  = 10 * time.Second
	nodeMaxAttempts  = 3
	nodeRetryDelay   = 500 * time.Millisecond
)

var mldsaScheme = mldsa87.Scheme()
var nodeHTTPClient = &http.Client{Timeout: nodeHTTPTimeout}

// ─── Sikka Types ──────────────────────────────────────────────────────────────

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
	ID                string     `json:"id,omitempty"`
	Parents           []string   `json:"parents"`
	ParentPowHashes   []string   `json:"parent_pow_hashes,omitempty"`
	Inputs            []TxInput  `json:"inputs"`
	Outputs           []TxOutput `json:"outputs"`
	PowNonce          int64      `json:"pow_nonce"`
	PowBits           int        `json:"pow_bits"`
	Timestamp         int64      `json:"timestamp"`
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

type TipsResponse struct {
	Tips []string `json:"tips"`
}

type PowQuoteRequest struct {
	Parents   []string `json:"parents"`
	Timestamp int64    `json:"timestamp"`
}

type PowQuoteResponse struct {
	RequiredBits      int      `json:"required_bits"`
	BaseBits          int      `json:"base_bits"`
	RecentCount       int      `json:"recent_count"`
	CongestionBuckets int      `json:"congestion_buckets"`
	WindowSeconds     int64    `json:"window_seconds"`
	BucketTx          int      `json:"bucket_tx"`
	BucketBits        int      `json:"bucket_bits"`
	OverrideBits      int      `json:"override_bits,omitempty"`
	ParentPowHashes   []string `json:"parent_pow_hashes"`
}

type SubmitResponse struct {
	TxID   string `json:"txid"`
	Status string `json:"status"`
}

type NodeStatus struct {
	Tips    []string `json:"tips"`
	DAGSize int64
}

// ─── Bot State ────────────────────────────────────────────────────────────────

type Bot struct {
	nodeURLs   []string
	faucetAddr string
	sk         []byte   // raw private key bytes
	pkHex      string
	db         *sql.DB
	guildID    string
}

// ─── Address Regex ────────────────────────────────────────────────────────────

var addrRe = regexp.MustCompile(`sikka1[` + bech32Charset + `]{6,}`)

// ─── Bech32m ──────────────────────────────────────────────────────────────────

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

// ─── Transaction Helpers ──────────────────────────────────────────────────────

func computeTxIDRaw(tx *Transaction) [32]byte {
	var buf []byte
	buf = append(buf, 0x02)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(tx.Parents)))
	for _, p := range tx.Parents {
		buf = append(buf, decodeHash32(p)...)
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

// txPowHash computes the SHA3-256 proof-of-work hash for a transaction.
// It hashes the stable txID, the two parent PoW hashes (tips commitment), and the
// pow_nonce. ParentPowHashes must be populated (from PoW quote) before mining.
func txPowHash(tx *Transaction) ([32]byte, error) {
	txIDBytes := computeTxIDRaw(tx)

	var p0, p1 [32]byte
	if len(tx.ParentPowHashes) >= 1 {
		if len(tx.ParentPowHashes[0]) != 64 {
			return [32]byte{}, fmt.Errorf("parent_pow_hashes[0] must be 64 hex chars")
		}
		b, err := hex.DecodeString(tx.ParentPowHashes[0])
		if err != nil {
			return [32]byte{}, fmt.Errorf("parent_pow_hashes[0]: %w", err)
		}
		copy(p0[:], b)
	}
	if len(tx.ParentPowHashes) >= 2 {
		if len(tx.ParentPowHashes[1]) != 64 {
			return [32]byte{}, fmt.Errorf("parent_pow_hashes[1] must be 64 hex chars")
		}
		b, err := hex.DecodeString(tx.ParentPowHashes[1])
		if err != nil {
			return [32]byte{}, fmt.Errorf("parent_pow_hashes[1]: %w", err)
		}
		copy(p1[:], b)
	}

	var buf [32 + 32 + 32 + 8]byte
	copy(buf[0:32], txIDBytes[:])
	copy(buf[32:64], p0[:])
	copy(buf[64:96], p1[:])
	binary.BigEndian.PutUint64(buf[96:], uint64(tx.PowNonce))
	return sha3.Sum256(buf[:]), nil
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
		hash, err := txPowHash(tx)
		if err != nil {
			return err
		}
		bits := leadingZeroBits(hash[:])
		if bits >= minBits {
			tx.PowBits = bits
			return nil
		}
	}
}

func leadingZeroBits(b []byte) int {
	count := 0
	for _, byt := range b {
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

func requiredPoWBits(outputCount int) int {
	const base = 20
	extra := outputCount - 1
	if extra < 0 {
		extra = 0
	}
	return base + extra
}

// ─── Wallet ───────────────────────────────────────────────────────────────────

// loadPrivateKey accepts a hex-encoded ML-DSA-87 private key or seed (32 bytes).
// Returns the raw private key bytes, public key hex, and faucet address.
func loadPrivateKey(privKeyHex string) (skBytes []byte, pkHex string, addr string, err error) {
	raw, err := hex.DecodeString(strings.TrimSpace(privKeyHex))
	if err != nil {
		return nil, "", "", fmt.Errorf("decode private key hex: %w", err)
	}

	var sk mldsa87.PrivateKey
	var pk mldsa87.PublicKey

	if len(raw) == mldsa87.SeedSize {
		// Treat as seed
		var seed [mldsa87.SeedSize]byte
		copy(seed[:], raw)
		pubKey, privKey := mldsa87.NewKeyFromSeed(&seed)
		pk = *pubKey
		sk = *privKey
	} else {
		// Treat as full private key
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

// ─── Node API ─────────────────────────────────────────────────────────────────

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

		resp, err := nodeHTTPClient.Do(req) //nolint:gosec // URL is from trusted env var
		if err == nil {
			if resp.StatusCode < http.StatusInternalServerError || attempt == nodeMaxAttempts {
				return resp, nil
			}

			lastErr = fmt.Errorf("status %d", resp.StatusCode)
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
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
	// Use max page size to retrieve as many UTXOs as possible in one request.
	// The server caps at 500; for very high UTXO counts we would need to page,
	// but 500 is sufficient for practical airdrop/tip wallet usage.
	url := fmt.Sprintf("%s/v1/address/%s?limit=500", strings.TrimRight(nodeURL, "/"), address)
	resp, err := doNodeRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("GET address: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GET address %d: %s", resp.StatusCode, body)
	}

	// New API returns paginated envelope: { "items": [...], "page": {...}, "meta": {address, balance, utxo_count} }
	type addressEnvelope struct {
		Items []UTXO `json:"items"`
		Meta  struct {
			Address   string `json:"address"`
			Balance   int64  `json:"balance"`
			UTXOCount int    `json:"utxo_count"`
		} `json:"meta"`
	}
	var env addressEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, fmt.Errorf("decode address info: %w", err)
	}

	info := AddressInfo{
		Address:   env.Meta.Address,
		Balance:   env.Meta.Balance,
		UTXOCount: env.Meta.UTXOCount,
		UTXOs:     env.Items,
	}
	if info.UTXOs == nil {
		info.UTXOs = []UTXO{}
	}
	if info.Address != "" && info.Address != address {
		return nil, fmt.Errorf("address response mismatch: requested %s, got %s", address, info.Address)
	}
	// Note: with limit we may have fewer UTXOs than utxo_count if >500; selection
	// will still work as long as the returned prefix covers the spend amount.
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
	validCount := 0

	for _, nodeURL := range nodeURLs {
		status, err := getNodeStatus(nodeURL)
		if err != nil {
			log.Printf("skip sikka node %s: %v", nodeURL, err)
			lastErr = err
			continue
		}

		validCount++
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
		// Mirror node's SelectTips() behaviour: duplicate the single tip.
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
	if len(quote.ParentPowHashes) != 2 {
		return nil, fmt.Errorf("pow quote missing or invalid parent_pow_hashes (expected 2)")
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

func (b *Bot) selectNodeURL() (string, error) {
	return selectBestNodeURL(b.nodeURLs)
}

// ─── Database ─────────────────────────────────────────────────────────────────

func initDB(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS claims (
			discord_user_id TEXT NOT NULL,
			claimed_at      INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_claims_user ON claims(discord_user_id);
	`)
	return err
}

// canClaim returns whether the user can claim. If not, it also returns the
// remaining cooldown duration.
func canClaim(db *sql.DB, userID string) (bool, time.Duration, error) {
	cutoff := time.Now().Add(-claimCooldown).Unix()
	var lastClaim int64
	err := db.QueryRow(
		`SELECT claimed_at FROM claims WHERE discord_user_id = ? AND claimed_at > ? ORDER BY claimed_at DESC LIMIT 1`,
		userID, cutoff,
	).Scan(&lastClaim)
	if err == sql.ErrNoRows {
		return true, 0, nil
	}
	if err != nil {
		return false, 0, err
	}
	remaining := time.Until(time.Unix(lastClaim, 0).Add(claimCooldown))
	if remaining <= 0 {
		return true, 0, nil
	}
	return false, remaining, nil
}

func recordClaim(db *sql.DB, userID string) error {
	_, err := db.Exec(
		`INSERT INTO claims (discord_user_id, claimed_at) VALUES (?, ?)`,
		userID, time.Now().Unix(),
	)
	return err
}

// ─── Send Airdrop ─────────────────────────────────────────────────────────────

func (b *Bot) sendAirdrop(recipientAddr string) (string, error) {
	nodeURL, err := b.selectNodeURL()
	if err != nil {
		return "", fmt.Errorf("select node: %w", err)
	}

	info, err := getAddressInfo(nodeURL, b.faucetAddr)
	if err != nil {
		return "", fmt.Errorf("fetch faucet balance: %w", err)
	}
	if info.Balance == 0 || len(info.UTXOs) == 0 {
		return "", fmt.Errorf("faucet is empty")
	}

	// 0.0001% of balance = balance / 1000000
	amount := info.Balance / airdropDivisor
	if amount < 1 {
		return "", fmt.Errorf("faucet balance too low to send (0.0001%% = %d chillar)", amount)
	}

	// Select UTXOs greedily
	var selected []UTXO
	var inputTotal int64
	for _, u := range info.UTXOs {
		selected = append(selected, u)
		inputTotal += u.Value
		if inputTotal >= amount {
			break
		}
	}
	if inputTotal < amount {
		return "", fmt.Errorf("insufficient UTXOs to cover send amount")
	}

	// Get 2 tips as parents
	tips, err := getTips(nodeURL)
	if err != nil {
		return "", err
	}

	// Build outputs
	outputs := []TxOutput{{Address: recipientAddr, Value: amount}}
	change := inputTotal - amount
	if change > 0 {
		outputs = append(outputs, TxOutput{Address: b.faucetAddr, Value: change})
	}

	// Build inputs (without witnesses yet)
	inputs := make([]TxInput, len(selected))
	for i, u := range selected {
		inputs[i] = TxInput{TxID: u.TxID, Index: u.Index}
	}

	tx := &Transaction{
		Parents:   tips,
		Inputs:    inputs,
		Outputs:   outputs,
		Timestamp: time.Now().Unix(),
	}

	// Sign each input
	for i, u := range selected {
		payload := signingPayload(tx, i, &u)
		sig, err := signInput(b.sk, payload)
		if err != nil {
			return "", fmt.Errorf("sign input %d: %w", i, err)
		}
		tx.Inputs[i].Witness = &TxWitness{
			Type: "threshold",
			Threshold: &ThresholdWitness{
				Threshold:  1,
				PublicKeys: []string{b.pkHex},
				Signatures: []string{sig},
			},
		}
	}

	quote, err := getPowQuote(nodeURL, tx)
	if err != nil {
		return "", fmt.Errorf("quote PoW: %w", err)
	}
	tx.ParentPowHashes = make([]string, len(quote.ParentPowHashes))
	copy(tx.ParentPowHashes, quote.ParentPowHashes)

	// Mine PoW using the node's live congestion-adjusted requirement.
	log.Printf("mining PoW (%d bits) for airdrop to %s...", quote.RequiredBits, recipientAddr)
	if err := minePoW(tx, quote.RequiredBits); err != nil {
		return "", fmt.Errorf("mine PoW: %w", err)
	}

	// Set the final tx ID
	txIDRaw := computeTxIDRaw(tx)
	tx.ID = hex.EncodeToString(txIDRaw[:])

	txID, err := submitTx(nodeURL, tx)
	if err != nil {
		return "", fmt.Errorf("submit tx: %w", err)
	}
	return txID, nil
}

// ─── Discord Handler ──────────────────────────────────────────────────────────

func (b *Bot) handleMessage(s *discordgo.Session, m *discordgo.MessageCreate) {
	if m.Author == nil || m.Author.Bot {
		return
	}
	if s.State != nil && s.State.User != nil && m.Author.ID == s.State.User.ID {
		return
	}
	if m.GuildID != b.guildID {
		return
	}

	matches := addrRe.FindAllString(m.Content, -1)
	if len(matches) == 0 {
		return
	}

	// Use the first valid sikka address found
	var recipientAddr string
	for _, candidate := range matches {
		normalized, err := validateAddress(candidate)
		if err == nil {
			recipientAddr = normalized
			break
		}
	}
	if recipientAddr == "" {
		return
	}

	// Don't send to the faucet itself
	if recipientAddr == b.faucetAddr {
		return
	}

	userID := m.Author.ID

	ok, remaining, err := canClaim(b.db, userID)
	if err != nil {
		log.Printf("canClaim error for %s: %v", userID, err)
		return
	}
	if !ok {
		h := int(remaining.Hours())
		min := int(remaining.Minutes()) % 60
		s.ChannelMessageSendReply(m.ChannelID, fmt.Sprintf( //nolint:errcheck
			"<@%s> You already claimed recently. Try again in **%dh %dm**.", userID, h, min,
		), m.Reference())
		return
	}

	// Record the claim before sending so we don't double-send on crash.
	if err := recordClaim(b.db, userID); err != nil {
		log.Printf("recordClaim error: %v", err)
		return
	}

	txID, err := b.sendAirdrop(recipientAddr)
	if err != nil {
		log.Printf("airdrop error to %s: %v", recipientAddr, err)
		s.ChannelMessageSendReply(m.ChannelID, fmt.Sprintf( //nolint:errcheck
			"<@%s> Airdrop failed: %s", userID, err.Error(),
		), m.Reference())
		return
	}

	// Get balance info for the success message
	nodeURL, err := b.selectNodeURL()
	if err != nil {
		log.Printf("select node for balance info: %v", err)
	}
	var info *AddressInfo
	if nodeURL != "" {
		info, _ = getAddressInfo(nodeURL, b.faucetAddr)
	}
	sentAmount := int64(0)
	if info != nil {
		sentAmount = info.Balance / airdropDivisor
	}

	s.ChannelMessageSendReply(m.ChannelID, fmt.Sprintf( //nolint:errcheck
		"<@%s> Sent **%s** to `%s`\nTx: `%s`",
		userID,
		formatSikkaDisplay(sentAmount),
		recipientAddr,
		txID,
	), m.Reference())
}

func formatSikka(chillar int64) string {
	whole := chillar / subunitsPerSikka
	frac := chillar % subunitsPerSikka
	if frac < 0 {
		frac = -frac
	}
	return fmt.Sprintf("%d.%010d", whole, frac)
}

func formatSikkaDisplay(chillar int64) string {
	abs := chillar
	if abs < 0 {
		abs = -abs
	}
	if abs < subunitsPerSikka {
		return fmt.Sprintf("%d chillar", chillar)
	}
	return fmt.Sprintf("%s SIKKA", formatSikka(chillar))
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	nodeURLs := parseNodeURLs(os.Getenv("sikkanode"))
	privKeyHex := os.Getenv("privatekey")
	discordToken := os.Getenv("discordtoken")
	guildID := os.Getenv("discordguild")

	if len(nodeURLs) == 0 {
		log.Fatal("env var 'sikkanode' is required and must contain at least one URL")
	}
	if privKeyHex == "" {
		log.Fatal("env var 'privatekey' is required")
	}
	if discordToken == "" {
		log.Fatal("env var 'discordtoken' is required")
	}
	if guildID == "" {
		log.Fatal("env var 'discordguild' is required")
	}

	selectedNodeURL, err := selectBestNodeURL(nodeURLs)
	if err != nil {
		log.Fatalf("select sikka node: %v", err)
	}
	log.Printf("using sikka node: %s", selectedNodeURL)

	// Load wallet
	skBytes, pkHex, faucetAddr, err := loadPrivateKey(privKeyHex)
	if err != nil {
		log.Fatalf("load private key: %v", err)
	}
	log.Printf("faucet address: %s", faucetAddr)

	// Open SQLite DB
	db, err := sql.Open("sqlite", "/data/claims.db")
	if err != nil {
		log.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := initDB(db); err != nil {
		log.Fatalf("init db: %v", err)
	}

	bot := &Bot{
		nodeURLs:   nodeURLs,
		faucetAddr: faucetAddr,
		sk:         skBytes,
		pkHex:      pkHex,
		db:         db,
		guildID:    guildID,
	}

	// Start Discord bot
	dg, err := discordgo.New("Bot " + discordToken)
	if err != nil {
		log.Fatalf("create discord session: %v", err)
	}
	dg.Identify.Intents = discordgo.IntentsGuildMessages | discordgo.IntentMessageContent
	dg.AddHandler(bot.handleMessage)

	if err := dg.Open(); err != nil {
		log.Fatalf("open discord connection: %v", err)
	}
	defer dg.Close()

	log.Println("Sikka airdrop bot running. Ctrl+C to stop.")
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM)
	<-sc
	log.Println("shutting down")
}
