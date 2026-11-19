package misgo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

const (
	miNASID         = "micoapi"
	miNABase        = "https://api2.mina.mi.com"
	miNAMedia       = "app_ios"
	miNAMediaPlayer = "mediaplayer"
)

// MiNAService controls XiaoAi speakers and retrieves their playback and query status.
type MiNAService struct {
	account  *MiAccount
	mu       sync.RWMutex
	hardware map[string]string
}

func NewMiNAService(account *MiAccount) *MiNAService {
	return &MiNAService{account: account}
}

// MiNARequest sends a GET with a nil form or a POST with a non-nil form.
func (m *MiNAService) MiNARequest(ctx context.Context, uri string, form url.Values) (map[string]any, error) {
	if m == nil || m.account == nil {
		return nil, errors.New("MiNA cloud requests require an account")
	}
	if !strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, "//") || strings.ContainsAny(uri, "#\r\n") {
		return nil, errors.New("invalid MiNA request URI")
	}
	id, err := RandomString(30)
	if err != nil {
		return nil, err
	}
	id = "app_ios_" + id
	if form == nil {
		sep := "?"
		if strings.Contains(uri, "?") {
			sep = "&"
		}
		uri += sep + "requestId=" + id
	} else {
		form = maps.Clone(form)
		form.Set("requestId", id)
	}
	return m.account.MiRequest(ctx, miNASID, miNABase+uri, form, http.Header{"User-Agent": {UAMiNA}})
}

func minaOption(fallback int, values []int) int {
	if len(values) != 0 {
		return values[0]
	}
	return fallback
}

// DeviceList returns the speakers for master (default 0) and caches their hardware models.
func (m *MiNAService) DeviceList(ctx context.Context, master ...int) ([]map[string]any, error) {
	result, err := m.MiNARequest(ctx, "/admin/v2/device_list?master="+strconv.Itoa(minaOption(0, master)), nil)
	if err != nil || result["data"] == nil {
		return nil, err
	}
	items, ok := result["data"].([]any)
	if !ok {
		return nil, errors.New("invalid MiNA device list")
	}
	devices := make([]map[string]any, len(items))
	for i, item := range items {
		devices[i], ok = item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid MiNA device at index %d", i)
		}
	}
	m.cacheDevices(devices)
	return devices, nil
}

func (m *MiNAService) cacheDevices(devices []map[string]any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, device := range devices {
		id, _ := device["deviceID"].(string)
		hardware, _ := device["hardware"].(string)
		if id != "" && hardware != "" {
			if m.hardware == nil {
				m.hardware = make(map[string]string)
			}
			m.hardware[id] = hardware
		}
	}
}

func (m *MiNAService) cachedHardware(deviceID string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.hardware[deviceID]
}

func (m *MiNAService) ubusRequest(ctx context.Context, deviceID, method, path string, message map[string]any) (map[string]any, error) {
	body, err := json.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("encode MiNA ubus message: %w", err)
	}
	return m.MiNARequest(ctx, "/remote/ubus", url.Values{
		"deviceId": {deviceID}, "message": {string(body)}, "method": {method}, "path": {path},
	})
}

// UbusRequest sends a device operation and reports whether the service accepted it.
func (m *MiNAService) UbusRequest(ctx context.Context, deviceID, method, path string, message map[string]any) (bool, error) {
	result, err := m.ubusRequest(ctx, deviceID, method, path, message)
	return result != nil && err == nil, err
}

func (m *MiNAService) TextToSpeech(ctx context.Context, deviceID, text string) (bool, error) {
	return m.UbusRequest(ctx, deviceID, "text_to_speech", "mibrain", map[string]any{"text": text})
}

func (m *MiNAService) PlayerSetVolume(ctx context.Context, deviceID string, volume int) (bool, error) {
	return m.UbusRequest(ctx, deviceID, "player_set_volume", miNAMediaPlayer, map[string]any{"volume": volume, "media": miNAMedia})
}

func (m *MiNAService) playerOperation(ctx context.Context, deviceID, action string) (bool, error) {
	return m.UbusRequest(ctx, deviceID, "player_play_operation", miNAMediaPlayer, map[string]any{"action": action, "media": miNAMedia})
}

func (m *MiNAService) PlayerPause(ctx context.Context, deviceID string) (bool, error) {
	return m.playerOperation(ctx, deviceID, "pause")
}

func (m *MiNAService) PlayerStop(ctx context.Context, deviceID string) (bool, error) {
	return m.playerOperation(ctx, deviceID, "stop")
}

func (m *MiNAService) PlayerPlay(ctx context.Context, deviceID string) (bool, error) {
	return m.playerOperation(ctx, deviceID, "play")
}

// PlayerGetStatus returns decoded data.info when it is JSON, or the raw data otherwise.
func (m *MiNAService) PlayerGetStatus(ctx context.Context, deviceID string) (any, error) {
	result, err := m.ubusRequest(ctx, deviceID, "player_get_play_status", miNAMediaPlayer, map[string]any{"media": miNAMedia})
	if err != nil {
		return nil, err
	}
	data := result["data"]
	if info, ok := minaObject(data)["info"].(string); ok {
		var value any
		if decodeAccountJSON([]byte(info), &value) == nil {
			return value, nil
		}
	}
	return data, nil
}

// PlayerSetLoop sets single-track (0), list (1, default), or random (2) playback
// for devices using the player_play_url API.
func (m *MiNAService) PlayerSetLoop(ctx context.Context, deviceID string, loop ...int) (bool, error) {
	return m.UbusRequest(ctx, deviceID, "player_set_loop", miNAMediaPlayer, map[string]any{"media": "common", "type": minaOption(1, loop)})
}

// PlayByURL chooses the playback API based on the speaker hardware.
func (m *MiNAService) PlayByURL(ctx context.Context, deviceID, audioURL string, typ ...int) (bool, error) {
	if m == nil {
		return false, errors.New("MiNA cloud requests require an account")
	}
	hardware := m.cachedHardware(deviceID)
	if hardware == "" {
		if _, err := m.DeviceList(ctx); err != nil {
			return false, err
		}
		hardware = m.cachedHardware(deviceID)
	}
	switch hardware {
	case "LX04", "LX05", "L05B", "L05C", "L06", "L06A",
		"X08A", "X10A", "X08C", "X08E", "X8F", "X4B", "OH2", "OH2P", "X6A":
		return m.PlayByMusicURL(ctx, deviceID, audioURL, typ...)
	default:
		return m.UbusRequest(ctx, deviceID, "player_play_url", miNAMediaPlayer, map[string]any{
			"url": audioURL, "type": minaOption(2, typ), "media": miNAMedia,
		})
	}
}

// PlayByMusicURL uses player_play_music with the default audio and provider IDs.
func (m *MiNAService) PlayByMusicURL(ctx context.Context, deviceID, audioURL string, typ ...int) (bool, error) {
	return m.PlayByMusicURLWithIDs(ctx, deviceID, audioURL, minaOption(2, typ), "1582971365183456177", "355454500")
}

// PlayByMusicURLWithIDs uses player_play_music with the given audio and provider IDs.
func (m *MiNAService) PlayByMusicURLWithIDs(ctx context.Context, deviceID, audioURL string, typ int, audioID, cpID string) (bool, error) {
	audioType := ""
	if typ == 1 {
		audioType = "MUSIC"
	}
	music, err := json.Marshal(map[string]any{
		"payload": map[string]any{
			"audio_type": audioType,
			"audio_items": []any{map[string]any{
				"item_id": map[string]any{"audio_id": audioID, "cp": map[string]any{
					"album_id": "-1", "episode_index": 0, "id": cpID, "name": "xiaowei",
				}},
				"stream": map[string]any{"url": audioURL},
			}},
			"list_params": map[string]any{"listId": "-1", "loadmore_offset": 0, "origin": "xiaowei", "type": "MUSIC"},
		},
		"play_behavior": "REPLACE_ALL",
	})
	if err != nil {
		return false, err
	}
	return m.UbusRequest(ctx, deviceID, "player_play_music", miNAMediaPlayer, map[string]any{"startaudioid": audioID, "music": string(music)})
}

func minaObject(value any) map[string]any {
	object, _ := value.(map[string]any)
	return object
}

func minaOr(object map[string]any, key string, fallback any) any {
	if value, ok := object[key]; ok {
		return value
	}
	return fallback
}

func minaTimestamp(value any) (int64, bool) {
	var n int64
	var err error
	switch value := value.(type) {
	case json.Number:
		n, err = value.Int64()
		if err != nil && strings.ContainsAny(string(value), ".eE") {
			f, err := value.Float64()
			if err == nil && f >= math.MinInt64 && f < -float64(math.MinInt64) {
				return int64(f), true
			}
		}
	case string:
		n, err = strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	case bool:
		if value {
			n = 1
		}
	default:
		return 0, false
	}
	return n, err == nil
}

// GetLatestAsk returns recent queries and their normalized answers.
func (m *MiNAService) GetLatestAsk(ctx context.Context, deviceID string) ([]map[string]any, error) {
	result, err := m.ubusRequest(ctx, deviceID, "nlp_result_get", "mibrain", map[string]any{})
	if err != nil {
		return nil, err
	}
	messages := make([]map[string]any, 0)
	data := minaObject(result["data"])
	if !isZeroCode(data["code"]) {
		return messages, nil
	}
	var payload struct{ Result []json.RawMessage }
	info, _ := data["info"].(string)
	if json.Unmarshal([]byte(info), &payload) != nil {
		return messages, nil
	}
	for _, entry := range payload.Result {
		var item struct{ NLP string }
		var nlp map[string]any
		if json.Unmarshal(entry, &item) != nil || decodeAccountJSON([]byte(item.NLP), &nlp) != nil || nlp == nil {
			continue
		}
		meta := minaObject(nlp["meta"])
		timestamp, ok := minaTimestamp(minaOr(meta, "timestamp", json.Number("0")))
		if !ok {
			continue
		}
		answers, ok := minaOr(minaObject(nlp["response"]), "answer", []any(nil)).([]any)
		if !ok {
			continue
		}
		normalized := make([]map[string]any, 0, len(answers))
		for _, item := range answers {
			a := minaObject(item)
			if a == nil {
				break
			}
			content := minaOr(a, "content", "")
			if object, ok := content.(map[string]any); ok {
				content = minaOr(object, "to_speak", "")
			}
			normalized = append(normalized, map[string]any{
				"domain":   minaOr(a, "domain", ""),
				"action":   minaOr(a, "action", ""),
				"content":  content,
				"question": minaOr(minaObject(a["intention"]), "query", ""),
			})
		}
		if len(normalized) == len(answers) {
			messages = append(messages, map[string]any{
				"request_id":   minaOr(meta, "request_id", ""),
				"timestamp_ms": timestamp,
				"response":     map[string]any{"answer": normalized},
			})
		}
	}
	return messages, nil
}

func minaTruthy(value any) bool {
	switch value := value.(type) {
	case nil:
		return false
	case bool:
		return value
	case string:
		return value != ""
	case json.Number:
		n, _ := value.Float64()
		return n != 0
	case float64:
		return value != 0
	case int:
		return value != 0
	case []any:
		return len(value) != 0
	case map[string]any:
		return len(value) != 0
	default:
		return true
	}
}

// SendMessage sets the volume and/or speaks on selected speakers, returning the
// last device operation's status. A selector of -1 broadcasts to all devices;
// otherwise the first matching one-based index or cloud TTS-capable device wins.
func (m *MiNAService) SendMessage(ctx context.Context, devices []map[string]any, devno int, message string, volume *int) (bool, error) {
	var result bool
	for i, device := range devices {
		if devno != -1 && devno != i+1 && !minaTruthy(minaObject(device["capabilities"])["yunduantts"]) {
			continue
		}
		deviceID, ok := device["deviceID"].(string)
		if !ok || deviceID == "" {
			return false, fmt.Errorf("MiNA device %d is missing deviceID", i+1)
		}
		var err error
		result = true
		if volume != nil {
			result, err = m.PlayerSetVolume(ctx, deviceID, *volume)
		}
		if result && message != "" {
			result, err = m.TextToSpeech(ctx, deviceID, message)
		}
		if err != nil || devno != -1 {
			return result, err
		}
	}
	return result, nil
}
