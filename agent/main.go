package main

import (
    "bytes"
    "context"
    "crypto/aes"
    "crypto/cipher"
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "log"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "sync"
    "time"
)

const protocolVersion = 1

type commandProfile struct {
    Executable     string   `json:"executable"`
    Args           []string `json:"args"`
    TimeoutSeconds int      `json:"timeout_seconds"`
}

type config struct {
    ListenAddr          string                    `json:"listen_addr"`
    SharedSecret        string                    `json:"shared_secret"`
    RootDir             string                    `json:"root_dir"`
    AllowFileWrite      bool                      `json:"allow_file_write"`
    MaxReadBytes        int64                     `json:"max_read_bytes"`
    MaxWriteBytes       int64                     `json:"max_write_bytes"`
    MaxOutputBytes      int                       `json:"max_output_bytes"`
    MaxClockSkewSeconds int64                     `json:"max_clock_skew_seconds"`
    Commands            map[string]commandProfile `json:"commands"`
}

type envelope struct {
    Version    int    `json:"v"`
    ID         string `json:"id"`
    Timestamp  int64  `json:"ts"`
    Nonce      string `json:"nonce"`
    Ciphertext string `json:"ct"`
    MAC        string `json:"mac"`
}

type relayRequest struct {
    Operation     string `json:"operation"`
    CommandID     string `json:"commandId,omitempty"`
    Path          string `json:"path,omitempty"`
    ContentBase64 string `json:"contentBase64,omitempty"`
    Encoding      string `json:"encoding,omitempty"`
    CallerID      string `json:"callerId,omitempty"`
}

type relayResponse struct {
    ID     string         `json:"id"`
    OK     bool           `json:"ok"`
    Result map[string]any `json:"result,omitempty"`
    Error  *relayError    `json:"error,omitempty"`
}

type relayError struct {
    Code    string `json:"code"`
    Message string `json:"message"`
}

type nonceCache struct {
    mu     sync.Mutex
    values map[string]time.Time
}

type app struct {
    config config
    secret []byte
    root   string
    nonces nonceCache
}

func main() {
    configPath := flag.String("config", "relay-agent.json", "path to agent JSON configuration")
    flag.Parse()

    raw, err := os.ReadFile(*configPath)
    if err != nil { log.Fatalf("read config: %v", err) }
    var cfg config
    if err := json.Unmarshal(raw, &cfg); err != nil { log.Fatalf("parse config: %v", err) }
    instance, err := newApp(cfg)
    if err != nil { log.Fatalf("invalid config: %v", err) }

    mux := http.NewServeMux()
    mux.HandleFunc("/v1/execute", instance.execute)
    server := &http.Server{Addr: instance.config.ListenAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 30 * time.Second}
    log.Printf("relay agent listening on %s", instance.config.ListenAddr)
    log.Fatal(server.ListenAndServe())
}

func newApp(cfg config) (*app, error) {
    if cfg.ListenAddr == "" { cfg.ListenAddr = "127.0.0.1:8787" }
    if cfg.MaxReadBytes <= 0 { cfg.MaxReadBytes = 64 * 1024 }
    if cfg.MaxWriteBytes <= 0 { cfg.MaxWriteBytes = 64 * 1024 }
    if cfg.MaxOutputBytes <= 0 { cfg.MaxOutputBytes = 64 * 1024 }
    if cfg.MaxClockSkewSeconds <= 0 { cfg.MaxClockSkewSeconds = 60 }
    if cfg.MaxReadBytes > 1024*1024 || cfg.MaxWriteBytes > 1024*1024 || cfg.MaxOutputBytes > 1024*1024 { return nil, errors.New("byte limits cannot exceed 1 MiB") }
    secret, err := base64.StdEncoding.DecodeString(cfg.SharedSecret)
    if err != nil || len(secret) != 32 { return nil, errors.New("shared_secret must be base64 encoded 32 bytes") }
    if cfg.RootDir == "" { return nil, errors.New("root_dir is required") }
    root, err := filepath.EvalSymlinks(cfg.RootDir)
    if err != nil { return nil, fmt.Errorf("resolve root_dir: %w", err) }
    info, err := os.Stat(root)
    if err != nil || !info.IsDir() { return nil, errors.New("root_dir must be an existing directory") }
    for id, command := range cfg.Commands {
        if id == "" || !filepath.IsAbs(command.Executable) || command.TimeoutSeconds < 1 || command.TimeoutSeconds > 25 { return nil, fmt.Errorf("unsafe command profile %q", id) }
        if isShell(filepath.Base(command.Executable)) { return nil, fmt.Errorf("shell profile %q is prohibited", id) }
    }
    return &app{config: cfg, secret: secret, root: root, nonces: nonceCache{values: make(map[string]time.Time)}}, nil
}

func (a *app) execute(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
    r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)
    defer r.Body.Close()
    var incoming envelope
    if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil { http.Error(w, "invalid request", http.StatusBadRequest); return }
    plaintext, err := a.open(incoming, "request")
    if err != nil { http.Error(w, "unauthorized", http.StatusUnauthorized); return }
    if !a.claimNonce(incoming.Nonce) { http.Error(w, "replayed request", http.StatusConflict); return }

    var request relayRequest
    if err := json.Unmarshal(plaintext, &request); err != nil { http.Error(w, "invalid request", http.StatusBadRequest); return }
    result := a.perform(request)
    result.ID = incoming.ID
    outgoing, err := a.seal(result, incoming.ID, "response")
    if err != nil { http.Error(w, "internal error", http.StatusInternalServerError); return }
    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("Cache-Control", "no-store")
    _ = json.NewEncoder(w).Encode(outgoing)
}

func (a *app) perform(request relayRequest) relayResponse {
    response := relayResponse{OK: false}
    switch request.Operation {
    case "command":
        response.Result, response.Error = a.runCommand(request.CommandID)
    case "read_file":
        response.Result, response.Error = a.readFile(request.Path)
    case "write_file":
        response.Result, response.Error = a.writeFile(request.Path, request.ContentBase64)
    default:
        response.Error = &relayError{Code: "OPERATION_DENIED", Message: "operation is not enabled"}
    }
    response.OK = response.Error == nil
    return response
}

func (a *app) runCommand(id string) (map[string]any, *relayError) {
    profile, ok := a.config.Commands[id]
    if !ok { return nil, &relayError{Code: "COMMAND_DENIED", Message: "command profile is not enabled"} }
    ctx, cancel := context.WithTimeout(context.Background(), time.Duration(profile.TimeoutSeconds)*time.Second)
    defer cancel()
    cmd := exec.CommandContext(ctx, profile.Executable, profile.Args...)
    cmd.Dir = a.root
    stdout, stderr := &limitedBuffer{limit: a.config.MaxOutputBytes}, &limitedBuffer{limit: a.config.MaxOutputBytes}
    cmd.Stdout, cmd.Stderr = stdout, stderr
    err := cmd.Run()
    exitCode := 0
    if err != nil {
        var exitError *exec.ExitError
        if errors.As(err, &exitError) { exitCode = exitError.ExitCode() } else if ctx.Err() != nil { return nil, &relayError{Code: "COMMAND_TIMEOUT", Message: "command deadline exceeded"} } else { return nil, &relayError{Code: "COMMAND_FAILED", Message: "command could not start"} }
    }
    return map[string]any{"exitCode": exitCode, "stdoutBase64": base64.StdEncoding.EncodeToString(stdout.Bytes()), "stderrBase64": base64.StdEncoding.EncodeToString(stderr.Bytes()), "truncated": stdout.truncated || stderr.truncated}, nil
}

func (a *app) readFile(path string) (map[string]any, *relayError) {
    resolved, err := a.resolveExisting(path)
    if err != nil { return nil, pathError(err) }
    info, err := os.Stat(resolved)
    if err != nil || !info.Mode().IsRegular() { return nil, &relayError{Code: "FILE_DENIED", Message: "only regular files may be read"} }
    if info.Size() > a.config.MaxReadBytes { return nil, &relayError{Code: "FILE_TOO_LARGE", Message: "file exceeds configured read limit"} }
    content, err := os.ReadFile(resolved)
    if err != nil { return nil, &relayError{Code: "FILE_READ_FAILED", Message: "file could not be read"} }
    return map[string]any{"contentBase64": base64.StdEncoding.EncodeToString(content), "bytes": len(content)}, nil
}

func (a *app) writeFile(path, contentBase64 string) (map[string]any, *relayError) {
    if !a.config.AllowFileWrite { return nil, &relayError{Code: "WRITE_DISABLED", Message: "file writes are disabled by remote policy"} }
    content, err := base64.StdEncoding.DecodeString(contentBase64)
    if err != nil || int64(len(content)) > a.config.MaxWriteBytes { return nil, &relayError{Code: "FILE_TOO_LARGE", Message: "invalid content or configured write limit exceeded"} }
    target, err := a.resolveWriteTarget(path)
    if err != nil { return nil, pathError(err) }
    temp, err := os.CreateTemp(filepath.Dir(target), ".mcp-relay-")
    if err != nil { return nil, &relayError{Code: "FILE_WRITE_FAILED", Message: "temporary file could not be created"} }
    tempName := temp.Name()
    defer os.Remove(tempName)
    if err := temp.Chmod(0600); err != nil { _ = temp.Close(); return nil, &relayError{Code: "FILE_WRITE_FAILED", Message: "file permissions could not be set"} }
    if _, err := temp.Write(content); err != nil { _ = temp.Close(); return nil, &relayError{Code: "FILE_WRITE_FAILED", Message: "file could not be written"} }
    if err := temp.Sync(); err != nil { _ = temp.Close(); return nil, &relayError{Code: "FILE_WRITE_FAILED", Message: "file could not be synced"} }
    if err := temp.Close(); err != nil { return nil, &relayError{Code: "FILE_WRITE_FAILED", Message: "file could not be closed"} }
    if err := os.Rename(tempName, target); err != nil { return nil, &relayError{Code: "FILE_WRITE_FAILED", Message: "file could not be replaced"} }
    return map[string]any{"bytes": len(content)}, nil
}

func (a *app) resolveExisting(value string) (string, error) {
    candidate, err := a.relativePath(value)
    if err != nil { return "", err }
    resolved, err := filepath.EvalSymlinks(candidate)
    if err != nil { return "", err }
    if !inside(a.root, resolved) { return "", errors.New("path escapes root") }
    return resolved, nil
}

func (a *app) resolveWriteTarget(value string) (string, error) {
    target, err := a.relativePath(value)
    if err != nil { return "", err }
    current := a.root
    relative, _ := filepath.Rel(a.root, filepath.Dir(target))
    for _, part := range strings.Split(relative, string(filepath.Separator)) {
        if part == "." || part == "" { continue }
        current = filepath.Join(current, part)
        info, err := os.Lstat(current)
        if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 { return "", errors.New("parent directory is not an existing regular directory") }
    }
    if info, err := os.Lstat(target); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) { return "", errors.New("target is not a regular file") } else if err != nil && !os.IsNotExist(err) { return "", err }
    return target, nil
}

func (a *app) relativePath(value string) (string, error) {
    if value == "" || filepath.IsAbs(value) || filepath.VolumeName(value) != "" { return "", errors.New("path must be relative") }
    cleaned := filepath.Clean(value)
    if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) { return "", errors.New("path traversal denied") }
    return filepath.Join(a.root, cleaned), nil
}

func isShell(name string) bool {
	switch name {
	case "sh", "bash", "dash", "zsh", "fish", "ksh", "busybox", "env":
		return true
	}
	return false
}

func inside(root, target string) bool {
    relative, err := filepath.Rel(root, target)
    return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func pathError(err error) *relayError { return &relayError{Code: "PATH_DENIED", Message: err.Error()} }

type limitedBuffer struct { bytes.Buffer; limit int; truncated bool }
func (b *limitedBuffer) Write(p []byte) (int, error) { remaining := b.limit - b.Len(); if remaining > 0 { if len(p) > remaining { _, _ = b.Buffer.Write(p[:remaining]); b.truncated = true } else { _, _ = b.Buffer.Write(p) } } else { b.truncated = true }; return len(p), nil }

func (a *app) claimNonce(nonce string) bool {
    now := time.Now()
    a.nonces.mu.Lock()
    defer a.nonces.mu.Unlock()
    for key, expiry := range a.nonces.values { if now.After(expiry) { delete(a.nonces.values, key) } }
    if _, exists := a.nonces.values[nonce]; exists { return false }
    a.nonces.values[nonce] = now.Add(time.Duration(a.config.MaxClockSkewSeconds) * time.Second * 2)
    return true
}

func (a *app) key(direction, purpose string) []byte {
    // HKDF-SHA256 with an empty salt; this mirrors Node's hkdfSync invocation.
    extract := hmac.New(sha256.New, make([]byte, sha256.Size)); extract.Write(a.secret)
    prk := extract.Sum(nil)
    expand := hmac.New(sha256.New, prk); expand.Write([]byte("mcp-secure-relay/v1/" + direction + "/" + purpose)); expand.Write([]byte{1})
    return expand.Sum(nil)[:32]
}

func envelopeAAD(v int, id string, timestamp int64, nonce string) []byte { return []byte(fmt.Sprintf("%d.%s.%d.%s", v, id, timestamp, nonce)) }

func (a *app) open(in envelope, direction string) ([]byte, error) {
    if in.Version != protocolVersion || in.ID == "" || time.Duration(abs(time.Now().UnixMilli()-in.Timestamp))*time.Millisecond > time.Duration(a.config.MaxClockSkewSeconds)*time.Second { return nil, errors.New("expired or invalid envelope") }
    nonce, err := base64.StdEncoding.DecodeString(in.Nonce); if err != nil || len(nonce) != 12 { return nil, errors.New("invalid nonce") }
    ciphertext, err := base64.StdEncoding.DecodeString(in.Ciphertext); if err != nil || len(ciphertext) < aes.BlockSize { return nil, errors.New("invalid ciphertext") }
    signer := hmac.New(sha256.New, a.key(direction, "hmac")); signer.Write(envelopeAAD(in.Version, in.ID, in.Timestamp, in.Nonce)); signer.Write([]byte(".")); signer.Write([]byte(in.Ciphertext))
    received, err := base64.StdEncoding.DecodeString(in.MAC); if err != nil || !hmac.Equal(received, signer.Sum(nil)) { return nil, errors.New("invalid mac") }
    block, err := aes.NewCipher(a.key(direction, "aes-gcm")); if err != nil { return nil, err }
    gcm, err := cipher.NewGCM(block); if err != nil { return nil, err }
    return gcm.Open(nil, nonce, ciphertext, envelopeAAD(in.Version, in.ID, in.Timestamp, in.Nonce))
}

func (a *app) seal(payload relayResponse, id, direction string) (envelope, error) {
    nonce := make([]byte, 12); if _, err := rand.Read(nonce); err != nil { return envelope{}, err }
    encodedNonce := base64.StdEncoding.EncodeToString(nonce)
    timestamp := time.Now().UnixMilli()
    plaintext, err := json.Marshal(payload); if err != nil { return envelope{}, err }
    block, err := aes.NewCipher(a.key(direction, "aes-gcm")); if err != nil { return envelope{}, err }
    gcm, err := cipher.NewGCM(block); if err != nil { return envelope{}, err }
    ciphertext := gcm.Seal(nil, nonce, plaintext, envelopeAAD(protocolVersion, id, timestamp, encodedNonce))
    encodedCiphertext := base64.StdEncoding.EncodeToString(ciphertext)
    signer := hmac.New(sha256.New, a.key(direction, "hmac")); signer.Write(envelopeAAD(protocolVersion, id, timestamp, encodedNonce)); signer.Write([]byte(".")); signer.Write([]byte(encodedCiphertext))
    return envelope{Version: protocolVersion, ID: id, Timestamp: timestamp, Nonce: encodedNonce, Ciphertext: encodedCiphertext, MAC: base64.StdEncoding.EncodeToString(signer.Sum(nil))}, nil
}

func abs(value int64) int64 { if value < 0 { return -value }; return value }
