package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip19"
	_ "modernc.org/sqlite"
)

const (
	defaultDBPath     = "/data/nostr.db"
	defaultEventLimit = 2 * time.Minute
	defaultOutboxTick = 15 * time.Second
	recentEventWindow = 10 * time.Minute
)

var tipCommandRe = regexp.MustCompile(`(?i)^sikka\s+tip(?:\s+([0-9]+(?:\.[0-9]{1,10})?))?(?:\s+@?(?:nostr:)?(npub[0-9a-z]+))?$`)

type Config struct {
	NodeURLs     []string
	RelayURLs    []string
	NostrSecret  string
	NostrPubKey  string
	NostrNPub    string
	RootSeed     []byte
	DBPath       string
	EventMaxAge  time.Duration
	MinTipAmount int64
	MaxTipAmount int64
	OutboxEvery  time.Duration
	SelectedNode string
}

type UserRecord struct {
	PubKey                 string
	DefaultWithdrawAddress sql.NullString
	DepositAddress         string
	DepositCredited        int64
	Available              int64
	Pending                int64
	CreatedAt              int64
}

type Bot struct {
	cfg      Config
	db       *sql.DB
	pool     *nostr.SimplePool
	recentMu  sync.Mutex
	recentIDs map[string]int64
	outboxMu  sync.Mutex
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	db, err := sql.Open("sqlite", cfg.DBPath)
	if err != nil {
		log.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.Exec(`PRAGMA busy_timeout = 5000`); err != nil {
		log.Fatalf("set sqlite busy_timeout: %v", err)
	}

	if err := initDB(db); err != nil {
		log.Fatalf("init db: %v", err)
	}

	pool := nostr.NewSimplePool(context.Background(), nostr.WithPenaltyBox())
	defer pool.Close("shutdown")

	bot := &Bot{
		cfg:      cfg,
		db:       db,
		pool:     pool,
		recentIDs: make(map[string]int64),
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := bot.run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("run bot: %v", err)
	}
	log.Println("shutting down")
}

func loadConfig() (Config, error) {
	nodeURLs := parseNodeURLs(getEnvAny("sikkanode", "SIKKANODE"))
	if len(nodeURLs) == 0 {
		return Config{}, fmt.Errorf("env var sikkanode is required")
	}
	relayURLs := parseRelayURLs(getEnvAny("nostrrelays", "NOSTRRELAYS"))
	if len(relayURLs) == 0 {
		return Config{}, fmt.Errorf("env var nostrrelays is required")
	}
	nsec := strings.TrimSpace(getEnvAny("nsec", "NSEC"))
	if nsec == "" {
		return Config{}, fmt.Errorf("env var nsec is required")
	}
	secretHex, seed, err := decodeNSEC(nsec)
	if err != nil {
		return Config{}, fmt.Errorf("decode nsec: %w", err)
	}
	pubKey, err := nostr.GetPublicKey(secretHex)
	if err != nil {
		return Config{}, fmt.Errorf("derive nostr pubkey: %w", err)
	}
	npub, err := nip19.EncodePublicKey(pubKey)
	if err != nil {
		return Config{}, fmt.Errorf("encode npub: %w", err)
	}
	selectedNode, err := selectBestNodeURL(nodeURLs)
	if err != nil {
		return Config{}, fmt.Errorf("select node: %w", err)
	}

	dbPath := strings.TrimSpace(getEnvAny("dbpath", "DBPATH"))
	if dbPath == "" {
		dbPath = defaultDBPath
	}

	eventMaxAge := defaultEventLimit
	if raw := strings.TrimSpace(getEnvAny("eventmaxage", "EVENTMAXAGE")); raw != "" {
		seconds, err := strconv.Atoi(raw)
		if err != nil || seconds < 1 {
			return Config{}, fmt.Errorf("invalid EVENTMAXAGE %q", raw)
		}
		eventMaxAge = time.Duration(seconds) * time.Second
	}

	minTip := int64(1)
	if raw := strings.TrimSpace(getEnvAny("mintip", "MINTIP")); raw != "" {
		parsed, err := parseAmount(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid MINTIP %q: %w", raw, err)
		}
		minTip = parsed
	}

	maxTip := int64(10_000_000) * subunitsPerSikka
	if raw := strings.TrimSpace(getEnvAny("maxtip", "MAXTIP")); raw != "" {
		parsed, err := parseAmount(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid MAXTIP %q: %w", raw, err)
		}
		maxTip = parsed
	}
	if minTip > maxTip {
		return Config{}, fmt.Errorf("MINTIP cannot exceed MAXTIP")
	}

	return Config{
		NodeURLs:     nodeURLs,
		RelayURLs:    relayURLs,
		NostrSecret:  secretHex,
		NostrPubKey:  pubKey,
		NostrNPub:    npub,
		RootSeed:     seed,
		DBPath:       dbPath,
		EventMaxAge:  eventMaxAge,
		MinTipAmount: minTip,
		MaxTipAmount: maxTip,
		OutboxEvery:  defaultOutboxTick,
		SelectedNode: selectedNode,
	}, nil
}

func getEnvAny(keys ...string) string {
	for _, key := range keys {
		if value := os.Getenv(key); strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func parseRelayURLs(raw string) []string {
	parts := strings.Split(raw, ",")
	urls := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		normalized := nostr.NormalizeURL(strings.TrimSpace(part))
		if normalized == "" || !nostr.IsValidRelayURL(normalized) {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		urls = append(urls, normalized)
	}
	return urls
}

func decodeNSEC(nsec string) (string, []byte, error) {
	prefix, value, err := nip19.Decode(strings.TrimSpace(nsec))
	if err != nil {
		return "", nil, err
	}
	if prefix != "nsec" {
		return "", nil, fmt.Errorf("unexpected nostr secret prefix %q", prefix)
	}
	secretHex, ok := value.(string)
	if !ok {
		return "", nil, fmt.Errorf("unexpected nsec payload type %T", value)
	}
	seed, err := hex.DecodeString(secretHex)
	if err != nil {
		return "", nil, err
	}
	if len(seed) != 32 {
		return "", nil, fmt.Errorf("unexpected nsec seed length %d", len(seed))
	}
	return secretHex, seed, nil
}

func initDB(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS nostr_users (
			pubkey TEXT PRIMARY KEY,
			created_at INTEGER NOT NULL,
			default_withdraw_address TEXT,
			deposit_address TEXT NOT NULL,
			deposit_credited INTEGER NOT NULL DEFAULT 0,
			dm_enabled INTEGER NOT NULL DEFAULT 1
		);
		CREATE TABLE IF NOT EXISTS balances (
			pubkey TEXT PRIMARY KEY,
			available INTEGER NOT NULL DEFAULT 0,
			pending INTEGER NOT NULL DEFAULT 0,
			updated_at INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS processed_events (
			event_id TEXT PRIMARY KEY,
			pubkey TEXT NOT NULL,
			kind INTEGER NOT NULL,
			relay_url TEXT,
			status TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			processed_at INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS tips (
			event_id TEXT PRIMARY KEY,
			sender_pubkey TEXT NOT NULL,
			recipient_pubkey TEXT NOT NULL,
			amount INTEGER NOT NULL,
			status TEXT NOT NULL,
			created_at INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS withdrawals (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			request_event_id TEXT UNIQUE,
			pubkey TEXT NOT NULL,
			address TEXT NOT NULL,
			amount INTEGER NOT NULL,
			txid TEXT,
			status TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS dm_outbox (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			recipient_pubkey TEXT NOT NULL,
			message_type TEXT NOT NULL,
			payload TEXT NOT NULL,
			status TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		);
	`)
	return err
}

func (b *Bot) run(ctx context.Context) error {
	go b.flushOutboxLoop(ctx)
	go func() {
		_ = b.flushOutbox(ctx)
	}()

	since := nostr.Timestamp(time.Now().Add(-b.cfg.EventMaxAge).Unix())
	publicFilter := nostr.Filter{
		Kinds: []int{nostr.KindTextNote},
		Since: &since,
	}
	dmFilter := nostr.Filter{
		Kinds: []int{nostr.KindEncryptedDirectMessage},
		Tags:  nostr.TagMap{"p": []string{b.cfg.NostrPubKey}},
		Since: &since,
	}

	publicReady := make(chan (<-chan nostr.RelayEvent), 1)
	dmReady := make(chan (<-chan nostr.RelayEvent), 1)
	go func() {
		publicReady <- b.pool.SubscribeMany(ctx, b.cfg.RelayURLs, publicFilter)
	}()
	go func() {
		dmReady <- b.pool.SubscribeMany(ctx, b.cfg.RelayURLs, dmFilter)
	}()

	var publicEvents <-chan nostr.RelayEvent
	var dmEvents <-chan nostr.RelayEvent

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ready, ok := <-publicReady:
			if !ok {
				publicReady = nil
				continue
			}
			publicEvents = ready
			publicReady = nil
		case ready, ok := <-dmReady:
			if !ok {
				dmReady = nil
				continue
			}
			dmEvents = ready
			dmReady = nil
		case relayEvent, ok := <-publicEvents:
			if !ok {
				publicEvents = nil
				if dmEvents == nil && publicReady == nil && dmReady == nil {
					return nil
				}
				continue
			}
			_ = b.handleRelayEvent(ctx, relayEvent)
		case relayEvent, ok := <-dmEvents:
			if !ok {
				dmEvents = nil
				if publicEvents == nil && publicReady == nil && dmReady == nil {
					return nil
				}
				continue
			}
			_ = b.handleRelayEvent(ctx, relayEvent)
		}
	}
}

func (b *Bot) handleRelayEvent(ctx context.Context, relayEvent nostr.RelayEvent) error {
	if relayEvent.Event == nil {
		return nil
	}
	relayURL := ""
	if relayEvent.Relay != nil {
		relayURL = relayEvent.Relay.URL
	}
	return b.handleEvent(ctx, relayURL, relayEvent.Event)
}

func (b *Bot) handleEvent(ctx context.Context, relayURL string, event *nostr.Event) error {
	if event == nil || event.PubKey == b.cfg.NostrPubKey {
		return nil
	}
	seen := b.trackRecentEvent(event)
	if !seen {
		return nil
	}
	valid, err := event.CheckSignature()
	if err != nil {
		return fmt.Errorf("verify signature: %w", err)
	}
	if !valid {
		return fmt.Errorf("invalid signature")
	}
	if !isFresh(event, b.cfg.EventMaxAge) {
		return fmt.Errorf("stale event")
	}

	switch event.Kind {
	case nostr.KindTextNote:
		amount, hasAmount, explicitRecipient, err := parseTipCommand(event.Content)
		if err != nil {
			return nil
		}
		recipientPubKey, err := b.resolveTipRecipient(ctx, event, explicitRecipient)
		if err != nil {
			return err
		}
		claimed, err := b.claimEvent(event, relayURL)
		if err != nil || !claimed {
			return err
		}
		if err := b.processTip(ctx, event, recipientPubKey, amount, hasAmount); err != nil {
			_ = b.updateProcessedStatus(event.ID, "failed")
			return err
		}
		return b.updateProcessedStatus(event.ID, "credited")
	case nostr.KindEncryptedDirectMessage:
		message, err := b.decryptDM(event)
		if err != nil {
			return fmt.Errorf("decrypt dm: %w", err)
		}
		claimed, err := b.claimEvent(event, relayURL)
		if err != nil || !claimed {
			return err
		}
		if err := b.processDM(ctx, event, message); err != nil {
			_ = b.updateProcessedStatus(event.ID, "failed")
			return err
		}
		return b.updateProcessedStatus(event.ID, "responded")
	default:
		return nil
	}
}

func isFresh(event *nostr.Event, maxAge time.Duration) bool {
	createdAt := event.CreatedAt.Time()
	now := time.Now()
	if createdAt.After(now.Add(maxAge)) {
		return false
	}
	return now.Sub(createdAt) <= maxAge
}

func parseTipCommand(content string) (int64, bool, string, error) {
	matches := tipCommandRe.FindStringSubmatch(strings.TrimSpace(content))
	if len(matches) == 0 {
		return 0, false, "", fmt.Errorf("not a tip command")
	}
	var (
		amount    int64
		hasAmount bool
		err       error
	)
	if matches[1] != "" {
		hasAmount = true
		amount, err = parseAmount(matches[1])
		if err != nil {
			return 0, false, "", err
		}
	}
	npub := matches[2]
	if npub == "" {
		return amount, hasAmount, "", nil
	}
	prefix, value, err := nip19.Decode(npub)
	if err != nil {
		return 0, false, "", fmt.Errorf("decode recipient npub: %w", err)
	}
	if prefix != "npub" {
		return 0, false, "", fmt.Errorf("recipient must be npub")
	}
	recipientPubKey, ok := value.(string)
	if !ok || !nostr.IsValidPublicKey(recipientPubKey) {
		return 0, false, "", fmt.Errorf("invalid recipient pubkey")
	}
	return amount, hasAmount, recipientPubKey, nil
}

func (b *Bot) trackRecentEvent(event *nostr.Event) bool {
	if event == nil {
		return false
	}
	now := time.Now()
	nowUnix := now.Unix()
	expiresAt := now.Add(recentEventWindow).Unix()

	b.recentMu.Lock()
	defer b.recentMu.Unlock()

	for eventID, expiry := range b.recentIDs {
		if expiry <= nowUnix {
			delete(b.recentIDs, eventID)
		}
	}

	if expiry, exists := b.recentIDs[event.ID]; exists && expiry > nowUnix {
		return false
	}

	b.recentIDs[event.ID] = expiresAt
	return true
}

func (b *Bot) resolveTipRecipient(ctx context.Context, event *nostr.Event, explicitRecipient string) (string, error) {
	if explicitRecipient != "" {
		return explicitRecipient, nil
	}
	recipient, err := b.resolveReplyRecipient(ctx, event)
	if err != nil {
		return "", err
	}
	if recipient == "" {
		return "", fmt.Errorf("tip command requires an npub or a reply target")
	}
	return recipient, nil
}

func (b *Bot) resolveReplyRecipient(ctx context.Context, event *nostr.Event) (string, error) {
	if event == nil {
		return "", nil
	}
	if replyEventID := findReplyEventID(event.Tags); replyEventID != "" {
		parent := b.pool.QuerySingle(ctx, b.cfg.RelayURLs, nostr.Filter{IDs: []string{replyEventID}, Limit: 1})
		if parent != nil && parent.Event != nil && parent.Event.PubKey != "" {
			if parent.Event.PubKey != event.PubKey && parent.Event.PubKey != b.cfg.NostrPubKey {
				return parent.Event.PubKey, nil
			}
		}
	}
	for i := len(event.Tags) - 1; i >= 0; i-- {
		tag := event.Tags[i]
		if len(tag) < 2 || tag[0] != "p" {
			continue
		}
		candidate := strings.TrimSpace(tag[1])
		if !nostr.IsValidPublicKey(candidate) {
			continue
		}
		if candidate == event.PubKey || candidate == b.cfg.NostrPubKey {
			continue
		}
		return candidate, nil
	}
	return "", nil
}

func findReplyEventID(tags nostr.Tags) string {
	var fallback string
	for _, tag := range tags {
		if len(tag) < 2 || tag[0] != "e" {
			continue
		}
		eventID := strings.TrimSpace(tag[1])
		if eventID == "" {
			continue
		}
		if len(tag) >= 4 {
			marker := strings.ToLower(strings.TrimSpace(tag[3]))
			if marker == "reply" {
				return eventID
			}
			if marker == "root" && fallback == "" {
				fallback = eventID
			}
		}
		if fallback == "" {
			fallback = eventID
		}
	}
	return fallback
}

func findRootEventID(tags nostr.Tags) string {
	for _, tag := range tags {
		if len(tag) < 4 || tag[0] != "e" {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(tag[3]), "root") {
			return strings.TrimSpace(tag[1])
		}
	}
	return findReplyEventID(tags)
}

func buildSikkaTxURL(txID string) string {
	return "https://sikka.click/tx/" + strings.TrimSpace(txID)
}

func parseAmount(raw string) (int64, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, fmt.Errorf("amount is required")
	}
	if strings.Count(value, ".") > 1 {
		return 0, fmt.Errorf("invalid amount %q", raw)
	}
	if !strings.Contains(value, ".") {
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse integer amount: %w", err)
		}
		if parsed <= 0 {
			return 0, fmt.Errorf("amount must be greater than zero")
		}
		return parsed, nil
	}
	parts := strings.SplitN(value, ".", 2)
	whole, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse whole amount: %w", err)
	}
	fracPart := parts[1]
	if len(fracPart) > 10 {
		return 0, fmt.Errorf("too many decimal places")
	}
	fracPart += strings.Repeat("0", 10-len(fracPart))
	frac, err := strconv.ParseInt(fracPart, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse fractional amount: %w", err)
	}
	amount := whole*subunitsPerSikka + frac
	if amount <= 0 {
		return 0, fmt.Errorf("amount must be greater than zero")
	}
	return amount, nil
}

func (b *Bot) claimEvent(event *nostr.Event, relayURL string) (bool, error) {
	_, err := b.db.Exec(
		`INSERT INTO processed_events (event_id, pubkey, kind, relay_url, status, created_at, processed_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.PubKey, event.Kind, relayURL, "received", event.CreatedAt.Time().Unix(), time.Now().Unix(),
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (b *Bot) updateProcessedStatus(eventID, status string) error {
	_, err := b.db.Exec(`UPDATE processed_events SET status = ?, processed_at = ? WHERE event_id = ?`, status, time.Now().Unix(), eventID)
	return err
}

func (b *Bot) ensureUser(pubKey string) (*UserRecord, error) {
	userWallet, err := deriveUserWallet(b.cfg.RootSeed, pubKey)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	_, err = b.db.Exec(
		`INSERT OR IGNORE INTO nostr_users (pubkey, created_at, deposit_address, deposit_credited, dm_enabled) VALUES (?, ?, ?, 0, 1)`,
		pubKey, now, userWallet.Address,
	)
	if err != nil {
		return nil, err
	}
	_, err = b.db.Exec(
		`INSERT OR IGNORE INTO balances (pubkey, available, pending, updated_at) VALUES (?, 0, 0, ?)`,
		pubKey, now,
	)
	if err != nil {
		return nil, err
	}

	rec := &UserRecord{}
	err = b.db.QueryRow(`
		SELECT u.pubkey, u.default_withdraw_address, u.deposit_address, u.deposit_credited,
		       b.available, b.pending, u.created_at
		FROM nostr_users u
		JOIN balances b ON b.pubkey = u.pubkey
		WHERE u.pubkey = ?`, pubKey,
	).Scan(&rec.PubKey, &rec.DefaultWithdrawAddress, &rec.DepositAddress, &rec.DepositCredited, &rec.Available, &rec.Pending, &rec.CreatedAt)
	if err != nil {
		return nil, err
	}
	return rec, nil
}

func (b *Bot) getWalletInfo(pubKey string) (*UserRecord, *AddressInfo, error) {
	user, err := b.ensureUser(pubKey)
	if err != nil {
		return nil, nil, err
	}
	info, err := getAddressInfo(b.cfg.SelectedNode, user.DepositAddress)
	if err != nil {
		return nil, nil, err
	}
	return user, info, nil
}

func (b *Bot) getUserWallet(pubKey string) (*Wallet, error) {
	return deriveUserWallet(b.cfg.RootSeed, pubKey)
}

func (b *Bot) processTip(ctx context.Context, event *nostr.Event, recipientPubKey string, amount int64, hasAmount bool) error {
	if event.PubKey == recipientPubKey {
		return fmt.Errorf("sender and recipient cannot match")
	}
	sender, senderInfo, err := b.getWalletInfo(event.PubKey)
	if err != nil {
		return err
	}
	senderWallet, err := b.getUserWallet(event.PubKey)
	if err != nil {
		return err
	}
	recipient, err := b.ensureUser(recipientPubKey)
	if err != nil {
		return err
	}
	if !hasAmount {
		amount = senderInfo.Balance / 100
		if amount <= 0 {
			return fmt.Errorf("available balance too low for default 1%% tip")
		}
	}
	if amount < b.cfg.MinTipAmount {
		return fmt.Errorf("tip amount below minimum")
	}
	if amount > b.cfg.MaxTipAmount {
		return fmt.Errorf("tip amount above maximum")
	}
	if senderInfo.Balance < amount {
		return fmt.Errorf("insufficient balance")
	}

	txID, err := sendExactAmount(b.cfg.SelectedNode, senderWallet, recipient.DepositAddress, amount)
	if err != nil {
		return fmt.Errorf("tip send failed: %w", err)
	}
	now := time.Now().Unix()
	_, _ = b.db.Exec(`INSERT OR REPLACE INTO tips (event_id, sender_pubkey, recipient_pubkey, amount, status, created_at) VALUES (?, ?, ?, ?, ?, ?)`, event.ID, event.PubKey, recipientPubKey, amount, "submitted", now)

	if sender != nil {
		_ = sender
	}
	log.Printf("nostr funds sent: type=tip amount=%s from=%s to=%s txid=%s", formatSikkaDisplay(amount), shortNPub(event.PubKey), shortNPub(recipient.PubKey), txID)
	b.publishTipReceipt(ctx, event, recipient.PubKey, amount, txID)

	txURL := buildSikkaTxURL(txID)
	if err := b.queueDM(recipientPubKey, "tip-received", fmt.Sprintf("You received %s from %s.\nTx: %s\nView: %s", formatSikkaDisplay(amount), shortNPub(event.PubKey), txID, txURL)); err != nil {
		return err
	}
	if err := b.queueDM(event.PubKey, "tip-sent", fmt.Sprintf("You sent %s to %s.\nTx: %s\nView: %s", formatSikkaDisplay(amount), shortNPub(recipient.PubKey), txID, txURL)); err != nil {
		return err
	}
	return b.flushOutbox(ctx)
}

func (b *Bot) reserveTip(ctx context.Context, eventID, senderPubKey, recipientPubKey string, amount int64) error {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now().Unix()
	result, err := tx.Exec(`UPDATE balances SET available = available - ?, pending = pending + ?, updated_at = ? WHERE pubkey = ? AND available >= ?`, amount, amount, now, senderPubKey, amount)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return fmt.Errorf("insufficient balance")
	}
	if _, err := tx.Exec(`INSERT INTO tips (event_id, sender_pubkey, recipient_pubkey, amount, status, created_at) VALUES (?, ?, ?, ?, ?, ?)`, eventID, senderPubKey, recipientPubKey, amount, "pending", now); err != nil {
		return err
	}
	return tx.Commit()
}

func (b *Bot) completeTip(eventID, senderPubKey string) error {
	tx, err := b.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now().Unix()
	if _, err := tx.Exec(`UPDATE tips SET status = ? WHERE event_id = ?`, "submitted", eventID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE balances SET pending = pending - COALESCE((SELECT amount FROM tips WHERE event_id = ?), 0), updated_at = ? WHERE pubkey = ?`, eventID, now, senderPubKey); err != nil {
		return err
	}
	return tx.Commit()
}

func (b *Bot) failTip(eventID, senderPubKey string, amount int64) error {
	tx, err := b.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now().Unix()
	if _, err := tx.Exec(`UPDATE tips SET status = ? WHERE event_id = ?`, "failed", eventID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE balances SET available = available + ?, pending = pending - ?, updated_at = ? WHERE pubkey = ?`, amount, amount, now, senderPubKey); err != nil {
		return err
	}
	return tx.Commit()
}

func (b *Bot) publishTipReceipt(ctx context.Context, tipEvent *nostr.Event, recipientPubKey string, amount int64, txID string) {
	if tipEvent == nil {
		return
	}
	message := fmt.Sprintf("Tip sent: %s to %s\nTx: %s\n%s", formatSikkaDisplay(amount), fullNPub(recipientPubKey), txID, buildSikkaTxURL(txID))
	_ = b.publishTextNote(ctx, message, buildReplyTags(tipEvent, recipientPubKey))
}

func buildReplyTags(event *nostr.Event, recipientPubKey string) nostr.Tags {
	if event == nil {
		return nil
	}
	tags := make(nostr.Tags, 0, 4)
	if rootEventID := findRootEventID(event.Tags); rootEventID != "" && rootEventID != event.ID {
		tags = append(tags, nostr.Tag{"e", rootEventID, "", "root"})
	}
	tags = append(tags, nostr.Tag{"e", event.ID, "", "reply"})
	tags = append(tags, nostr.Tag{"p", event.PubKey})
	if recipientPubKey != "" && recipientPubKey != event.PubKey {
		tags = append(tags, nostr.Tag{"p", recipientPubKey})
	}
	return tags
}

func (b *Bot) processDM(ctx context.Context, event *nostr.Event, plaintext string) error {
	if _, err := b.ensureUser(event.PubKey); err != nil {
		return err
	}
	command := strings.TrimSpace(plaintext)
	if command == "" {
		return b.queueAndFlush(ctx, event.PubKey, "help", helpMessage())
	}

	fields := strings.Fields(command)
	if len(fields) == 0 {
		return b.queueAndFlush(ctx, event.PubKey, "help", helpMessage())
	}

	switch strings.ToLower(fields[0]) {
	case "help":
		return b.queueAndFlush(ctx, event.PubKey, "help", helpMessage())
	case "balance":
		return b.handleBalance(ctx, event.PubKey)
	case "deposit":
		return b.handleDeposit(ctx, event.PubKey)
	case "address":
		if len(fields) < 3 || strings.ToLower(fields[1]) != "set" {
			return b.queueAndFlush(ctx, event.PubKey, "error", "Usage: address set <sikka-address>")
		}
		return b.handleAddressSet(ctx, event.PubKey, fields[2])
	case "withdraw":
		return b.handleWithdraw(ctx, event.PubKey, event.ID, fields[1:])
	default:
		return b.queueAndFlush(ctx, event.PubKey, "help", helpMessage())
	}
}

func (b *Bot) handleBalance(ctx context.Context, pubKey string) error {
	rec, info, err := b.getWalletInfo(pubKey)
	if err != nil {
		return err
	}
	message := fmt.Sprintf("Available: %s\nDeposit address: %s", formatSikkaDisplay(info.Balance), rec.DepositAddress)
	if rec.DefaultWithdrawAddress.Valid {
		message += fmt.Sprintf("\nDefault withdraw address: %s", rec.DefaultWithdrawAddress.String)
	}
	return b.queueAndFlush(ctx, pubKey, "balance", message)
}

func (b *Bot) handleDeposit(ctx context.Context, pubKey string) error {
	rec, info, err := b.getWalletInfo(pubKey)
	if err != nil {
		return err
	}
	message := fmt.Sprintf("Deposit to: %s\nCurrent on-chain balance: %s", rec.DepositAddress, formatSikkaDisplay(info.Balance))
	return b.queueAndFlush(ctx, pubKey, "deposit", message)
}

func (b *Bot) handleAddressSet(ctx context.Context, pubKey, address string) error {
	normalized, err := validateAddress(address)
	if err != nil {
		return b.queueAndFlush(ctx, pubKey, "error", fmt.Sprintf("Invalid address: %v", err))
	}
	_, err = b.db.Exec(`UPDATE nostr_users SET default_withdraw_address = ? WHERE pubkey = ?`, normalized, pubKey)
	if err != nil {
		return err
	}
	return b.queueAndFlush(ctx, pubKey, "address-set", fmt.Sprintf("Default withdraw address set to %s", normalized))
}

func (b *Bot) handleWithdraw(ctx context.Context, pubKey, requestEventID string, args []string) error {
	if len(args) == 0 {
		return b.queueAndFlush(ctx, pubKey, "error", "Usage: withdraw all <address> | withdraw <amount> <address>")
	}

	user, info, err := b.getWalletInfo(pubKey)
	if err != nil {
		return err
	}
	wallet, err := b.getUserWallet(pubKey)
	if err != nil {
		return err
	}

	var amount int64
	var address string
	if strings.EqualFold(args[0], "all") {
		amount = info.Balance
		if len(args) > 1 {
			address = args[1]
		} else if user.DefaultWithdrawAddress.Valid {
			address = user.DefaultWithdrawAddress.String
		}
	} else {
		amount, err = parseAmount(args[0])
		if err != nil {
			return b.queueAndFlush(ctx, pubKey, "error", fmt.Sprintf("Invalid amount: %v", err))
		}
		if len(args) > 1 {
			address = args[1]
		} else if user.DefaultWithdrawAddress.Valid {
			address = user.DefaultWithdrawAddress.String
		}
	}
	if amount <= 0 {
		return b.queueAndFlush(ctx, pubKey, "error", "No withdrawable balance available")
	}
	if info.Balance < amount {
		return b.queueAndFlush(ctx, pubKey, "error", "Insufficient on-chain balance")
	}
	normalized, err := validateAddress(address)
	if err != nil {
		return b.queueAndFlush(ctx, pubKey, "error", fmt.Sprintf("Invalid withdraw address: %v", err))
	}

	txID, err := sendExactAmount(b.cfg.SelectedNode, wallet, normalized, amount)
	if err != nil {
		return b.queueAndFlush(ctx, pubKey, "error", fmt.Sprintf("Withdrawal failed: %v", err))
	}
	now := time.Now().Unix()
	_, _ = b.db.Exec(`INSERT OR REPLACE INTO withdrawals (request_event_id, pubkey, address, amount, txid, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, requestEventID, pubKey, normalized, amount, txID, "completed", now, now)
	log.Printf("nostr funds sent: type=withdrawal amount=%s from=%s to=%s txid=%s", formatSikkaDisplay(amount), shortNPub(pubKey), normalized, txID)
	return b.queueAndFlush(ctx, pubKey, "withdrawal", fmt.Sprintf("Withdrawal sent: %s\nAddress: %s\nTx: %s", formatSikkaDisplay(amount), normalized, txID))
}

func (b *Bot) reserveWithdrawal(ctx context.Context, requestEventID, pubKey, address string, amount int64) (int64, error) {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	now := time.Now().Unix()
	result, err := tx.Exec(`UPDATE balances SET available = available - ?, pending = pending + ?, updated_at = ? WHERE pubkey = ? AND available >= ?`, amount, amount, now, pubKey, amount)
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if affected != 1 {
		return 0, fmt.Errorf("insufficient balance")
	}
	res, err := tx.Exec(`INSERT INTO withdrawals (request_event_id, pubkey, address, amount, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, requestEventID, pubKey, address, amount, "pending", now, now)
	if err != nil {
		return 0, err
	}
	withdrawalID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return withdrawalID, nil
}

func (b *Bot) completeWithdrawal(withdrawalID int64, txID string) error {
	tx, err := b.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	if _, err := tx.Exec(`
		UPDATE withdrawals
		SET status = ?, txid = ?, updated_at = ?
		WHERE id = ?`,
		"completed", txID, now, withdrawalID,
	); err != nil {
		return err
	}
	if _, err := tx.Exec(`
		UPDATE balances
		SET pending = pending - COALESCE((SELECT amount FROM withdrawals WHERE id = ?), 0), updated_at = ?
		WHERE pubkey = (SELECT pubkey FROM withdrawals WHERE id = ?)`,
		withdrawalID, now, withdrawalID,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func (b *Bot) failWithdrawal(withdrawalID int64, pubKey string, amount int64) error {
	tx, err := b.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	if _, err := tx.Exec(`UPDATE withdrawals SET status = ?, updated_at = ? WHERE id = ?`, "failed", now, withdrawalID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE balances SET available = available + ?, pending = pending - ?, updated_at = ? WHERE pubkey = ?`, amount, amount, now, pubKey); err != nil {
		return err
	}
	return tx.Commit()
}

func (b *Bot) syncDeposits(pubKey string) (int64, error) {
	return 0, nil
}

func (b *Bot) decryptDM(event *nostr.Event) (string, error) {
	shared, err := nip04.ComputeSharedSecret(event.PubKey, b.cfg.NostrSecret)
	if err != nil {
		return "", err
	}
	return nip04.Decrypt(event.Content, shared)
}

func (b *Bot) queueDM(recipientPubKey, messageType, payload string) error {
	now := time.Now().Unix()
	_, err := b.db.Exec(`INSERT INTO dm_outbox (recipient_pubkey, message_type, payload, status, created_at, updated_at) VALUES (?, ?, ?, 'pending', ?, ?)`, recipientPubKey, messageType, payload, now, now)
	return err
}

func (b *Bot) queueAndFlush(ctx context.Context, recipientPubKey, messageType, payload string) error {
	if err := b.queueDM(recipientPubKey, messageType, payload); err != nil {
		return err
	}
	return b.flushOutbox(ctx)
}

func (b *Bot) flushOutboxLoop(ctx context.Context) {
	ticker := time.NewTicker(b.cfg.OutboxEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = b.flushOutbox(ctx)
		}
	}
}

func (b *Bot) flushOutbox(ctx context.Context) error {
	b.outboxMu.Lock()
	defer b.outboxMu.Unlock()

	type outboxEntry struct {
		id              int64
		recipientPubKey string
		messageType     string
		payload         string
	}

	rows, err := b.db.Query(`SELECT id, recipient_pubkey, message_type, payload FROM dm_outbox WHERE status = 'pending' ORDER BY id ASC LIMIT 20`)
	if err != nil {
		return err
	}

	entries := make([]outboxEntry, 0, 20)

	for rows.Next() {
		var entry outboxEntry
		if err := rows.Scan(&entry.id, &entry.recipientPubKey, &entry.messageType, &entry.payload); err != nil {
			rows.Close()
			return err
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}

	for _, entry := range entries {
		claimed, err := b.claimOutboxRow(entry.id)
		if err != nil {
			return err
		}
		if !claimed {
			continue
		}
		if err := b.sendDM(ctx, entry.recipientPubKey, entry.payload); err != nil {
			_, _ = b.db.Exec(`UPDATE dm_outbox SET status = 'failed', updated_at = ? WHERE id = ?`, time.Now().Unix(), entry.id)
			continue
		}
		_, _ = b.db.Exec(`UPDATE dm_outbox SET status = 'sent', updated_at = ? WHERE id = ?`, time.Now().Unix(), entry.id)
	}
	return nil
}

func (b *Bot) claimOutboxRow(id int64) (bool, error) {
	result, err := b.db.Exec(`UPDATE dm_outbox SET status = 'sending', updated_at = ? WHERE id = ? AND status = 'pending'`, time.Now().Unix(), id)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected == 1, nil
}

func (b *Bot) sendDM(ctx context.Context, recipientPubKey, message string) error {
	shared, err := nip04.ComputeSharedSecret(recipientPubKey, b.cfg.NostrSecret)
	if err != nil {
		return err
	}
	encrypted, err := nip04.Encrypt(message, shared)
	if err != nil {
		return err
	}
	event := nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      nostr.KindEncryptedDirectMessage,
		Tags:      nostr.Tags{nostr.Tag{"p", recipientPubKey}},
		Content:   encrypted,
	}
	if err := event.Sign(b.cfg.NostrSecret); err != nil {
		return err
	}
	results := b.pool.PublishMany(ctx, b.cfg.RelayURLs, event)
	success := false
	for result := range results {
		if result.Error == nil {
			success = true
			continue
		}
	}
	if !success {
		return fmt.Errorf("publish failed on all relays")
	}
	return nil
}

func (b *Bot) publishTextNote(ctx context.Context, message string, tags nostr.Tags) error {
	event := nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      nostr.KindTextNote,
		Tags:      tags,
		Content:   message,
	}
	if err := event.Sign(b.cfg.NostrSecret); err != nil {
		return err
	}
	results := b.pool.PublishMany(ctx, b.cfg.RelayURLs, event)
	success := false
	for result := range results {
		if result.Error == nil {
			success = true
		}
	}
	if !success {
		return fmt.Errorf("publish failed on all relays")
	}
	return nil
}

func helpMessage() string {
	return strings.Join([]string{
		"SIKKA Nostr wallet",
		"",
		"Available commands:",
		"help - show this message",
		"balance - check your current on-chain wallet balance",
		"deposit - get your personal SIKKA deposit address",
		"address set <sikka-address> - save a default withdrawal address",
		"withdraw all <address> - send your full wallet balance",
		"withdraw <amount> <address> - send a specific amount",
		"",
		"Amounts without a decimal are atomic units. Decimals are interpreted as SIKKA.",
		"",
		"Project and source:",
		"https://gitworkshop.dev/npub1x6au4qgw9t403yushl34tgngmgcaqv9yna7ywf8e6x4xf686ln7qc7y6wq/sikka",
		"",
		"Open the full wallet interface:",
		"https://sikka.click",
	}, "\n")
}

func shortNPub(pubKey string) string {
	npub, err := nip19.EncodePublicKey(pubKey)
	if err != nil {
		return pubKey
	}
	if len(npub) <= 18 {
		return npub
	}
	return npub[:12] + "..." + npub[len(npub)-6:]
}

func fullNPub(pubKey string) string {
	npub, err := nip19.EncodePublicKey(pubKey)
	if err != nil {
		return shortNPub(pubKey)
	}
	return "nostr:" + npub
}

func previewText(value string, maxLen int) string {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.ReplaceAll(trimmed, "\n", "\\n")
	if maxLen <= 0 || len(trimmed) <= maxLen {
		return trimmed
	}
	return trimmed[:maxLen] + "..."
}
