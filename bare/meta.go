package bare

import (
	"sync"
	"time"
)

type Database interface {
	Get(key string) (string, error)
	Set(key string, value string, expiration time.Duration) error
	Delete(key string) error
}

type MemoryDatabase struct {
	data        map[string]string
	expirations map[string]time.Time
	mutex       sync.RWMutex
}

func NewMemoryDatabase() *MemoryDatabase {
	db := &MemoryDatabase{
		data:        make(map[string]string),
		expirations: make(map[string]time.Time),
		mutex:       sync.RWMutex{},
	}
	go db.cleanupExpiredKeys()
	return db
}

func (db *MemoryDatabase) Get(key string) (string, error) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	if expiration, ok := db.expirations[key]; ok {
		if time.Now().After(expiration) {
			delete(db.data, key)
			delete(db.expirations, key)
			return "", nil
		}
	}

	value, ok := db.data[key]
	if !ok {
		return "", nil
	}
	return value, nil
}

func (db *MemoryDatabase) Set(key string, value string, expiration time.Duration) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	db.data[key] = value
	db.expirations[key] = time.Now().Add(expiration)
	return nil
}

func (db *MemoryDatabase) Delete(key string) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	delete(db.data, key)
	delete(db.expirations, key)
	return nil
}

func (db *MemoryDatabase) cleanupExpiredKeys() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		<-ticker.C

		db.mutex.Lock()
		for key, expiration := range db.expirations {
			if time.Now().After(expiration) {
				delete(db.data, key)
				delete(db.expirations, key)
			}
		}
		db.mutex.Unlock()
	}
}

type JSONDatabaseAdapter struct {
	db Database
}

func NewJSONDatabaseAdapter(db Database) *JSONDatabaseAdapter {
	return &JSONDatabaseAdapter{db: db}
}

func (jda *JSONDatabaseAdapter) Get(key string) (string, error) {
	return jda.db.Get(key)
}

func (jda *JSONDatabaseAdapter) Set(key string, value string, expiration time.Duration) error {
	return jda.db.Set(key, value, expiration)
}

func (jda *JSONDatabaseAdapter) Delete(key string) error {
	return jda.db.Delete(key)
}
