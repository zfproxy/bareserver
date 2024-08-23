package bare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
)

type BareLanguage string

const (
	LanguageNodeJS        BareLanguage = "NodeJS"
	LanguageServiceWorker BareLanguage = "ServiceWorker"
	LanguageDeno          BareLanguage = "Deno"
	LanguageJava          BareLanguage = "Java"
	LanguagePHP           BareLanguage = "PHP"
	LanguageRust          BareLanguage = "Rust"
	LanguageC             BareLanguage = "C"
	LanguageCPlusPlus     BareLanguage = "C++"
	LanguageCSharp        BareLanguage = "C#"
	LanguageRuby          BareLanguage = "Ruby"
	LanguageGo            BareLanguage = "Go"
	LanguageCrystal       BareLanguage = "Crystal"
	LanguageShell         BareLanguage = "Shell"
)

type BareManifest struct {
	Maintainer  *BareMaintainer `json:"maintainer,omitempty"`
	Project     *BareProject    `json:"project,omitempty"`
	Versions    []string        `json:"versions"`
	Language    BareLanguage    `json:"language"`
	MemoryUsage float64         `json:"memoryUsage,omitempty"`
}

func (s *BareServer) getInstanceInfo() io.ReadCloser {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	if s.options.Maintainer == nil && len(s.options.MaintainerFile) != 0 {
		data, err := os.ReadFile(s.options.MaintainerFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading maintainer file: %s\n", err)

		}
		if err := json.Unmarshal(data, &s.options.Maintainer); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing maintainer data: %s\n", err)
		}
	}

	info := BareManifest{
		Versions:    s.versions,
		Language:    LanguageGo,
		MemoryUsage: float64(memStats.HeapAlloc) / 1024 / 1024,
		Maintainer:  s.options.Maintainer,
		Project: &BareProject{
			Name:        "bare-server-go",
			Description: "Bare server implementation in Go",
			Repository:  "https://github.com/genericness/bare-server-go",
			Version:     "0.1.0",
		},
	}

	jsonData, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		panic(err)
	}

	return io.NopCloser(bytes.NewReader(jsonData))
}
