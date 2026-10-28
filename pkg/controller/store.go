package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// StoreStateKey is the ConfigMap key that carries the serialised ownership
// map.
const StoreStateKey = "state"

// storeRetries bounds the optimistic-retry loop of a mutating store call. A
// conflict means another writer changed the ConfigMap between the read and the
// write, so the caller re-reads and retries; a persistent conflict is reported
// rather than retried forever.
const storeRetries = 5

// Store is a ConfigMap-backed map from a Service to the provider objects
// senselb owns for it.
//
// Keys are "<namespace>/<service>/<object>", where <object> names the HAProxy
// object in the provider's own vocabulary (for example a backend name). The
// whole map is serialised as one JSON document under StoreStateKey, so the
// ConfigMap is a single object with a single resource version.
//
// The ConfigMap is created on demand by the first Put and has no owner: it
// outlives any one Service, because it is the inventory the apply pipeline
// rebuilds the desired model from. It must never hold credentials, and it does
// not: a value is an opaque provider object identifier, not a secret.
//
// Writes are serialised inside one process by a mutex, and a write that loses a
// race with another controller instance is retried after a fresh read, bounded
// by storeRetries. Concurrent Put calls therefore never drop an entry.
type Store struct {
	Client    client.Client
	Namespace string
	Name      string

	mu sync.Mutex
}

// Get returns the object identifier recorded for key.
func (s *Store) Get(ctx context.Context, key string) (string, bool, error) {
	state, err := s.read(ctx)
	if err != nil {
		return "", false, err
	}
	value, ok := state[key]
	return value, ok, nil
}

// Put records uuid for key, creating the ConfigMap or the entry as needed.
func (s *Store) Put(ctx context.Context, key, uuid string) error {
	return s.mutate(ctx, func(state map[string]string) bool {
		if state[key] == uuid {
			return false
		}
		state[key] = uuid
		return true
	})
}

// Delete removes key. Deleting an absent key is a no-op and writes nothing.
func (s *Store) Delete(ctx context.Context, key string) error {
	return s.mutate(ctx, func(state map[string]string) bool {
		if _, present := state[key]; !present {
			return false
		}
		delete(state, key)
		return true
	})
}

// ForService returns the keys owned by one Service, sorted. A Service with no
// entries yields an empty slice and no error.
func (s *Store) ForService(ctx context.Context, namespace, name string) ([]string, error) {
	state, err := s.read(ctx)
	if err != nil {
		return nil, err
	}
	prefix := namespace + "/" + name + "/"
	var keys []string
	for key := range state {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	return keys, nil
}

// ManagedServices returns every distinct Service with at least one entry in the
// store, sorted by namespace and then name. Node and EndpointSlice events fan
// out to this list.
func (s *Store) ManagedServices(ctx context.Context) ([]types.NamespacedName, error) {
	state, err := s.read(ctx)
	if err != nil {
		return nil, err
	}

	seen := make(map[types.NamespacedName]struct{}, len(state))
	for key := range state {
		parts := strings.SplitN(key, "/", 3)
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
			// A key that does not follow the convention cannot be attributed
			// to a Service; skip it rather than fail the whole listing.
			continue
		}
		seen[types.NamespacedName{Namespace: parts[0], Name: parts[1]}] = struct{}{}
	}

	services := make([]types.NamespacedName, 0, len(seen))
	for service := range seen {
		services = append(services, service)
	}
	slices.SortFunc(services, func(a, b types.NamespacedName) int {
		if c := strings.Compare(a.Namespace, b.Namespace); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	return services, nil
}

// read returns the current state, treating a missing ConfigMap as empty.
func (s *Store) read(ctx context.Context) (map[string]string, error) {
	configMap := &corev1.ConfigMap{}
	err := s.Client.Get(ctx, s.objectKey(), configMap)
	if apierrors.IsNotFound(err) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read ownership store %s: %w", s.objectKey(), err)
	}
	return decodeState(configMap)
}

// mutate applies change to the state and persists the result. change reports
// whether it altered the map, so a no-op call writes nothing.
func (s *Store) mutate(ctx context.Context, change func(map[string]string) bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var lastErr error
	for attempt := 0; attempt < storeRetries; attempt++ {
		state, configMap, err := s.load(ctx)
		if err != nil {
			return err
		}
		if !change(state) {
			return nil
		}
		encoded, err := json.Marshal(state)
		if err != nil {
			return fmt.Errorf("encode ownership store %s: %w", s.objectKey(), err)
		}

		if configMap == nil {
			configMap = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: s.Namespace, Name: s.Name},
				Data:       map[string]string{StoreStateKey: string(encoded)},
			}
			if err := s.Client.Create(ctx, configMap); err != nil {
				if apierrors.IsAlreadyExists(err) || apierrors.IsConflict(err) {
					lastErr = err
					continue
				}
				return fmt.Errorf("create ownership store %s: %w", s.objectKey(), err)
			}
			return nil
		}

		if configMap.Data == nil {
			configMap.Data = make(map[string]string, 1)
		}
		configMap.Data[StoreStateKey] = string(encoded)
		if err := s.Client.Update(ctx, configMap); err != nil {
			if apierrors.IsConflict(err) {
				lastErr = err
				continue
			}
			return fmt.Errorf("update ownership store %s: %w", s.objectKey(), err)
		}
		return nil
	}
	return fmt.Errorf("update ownership store %s after %d attempts: %w", s.objectKey(), storeRetries, lastErr)
}

// load returns the current state together with the live ConfigMap, so a caller
// can update the object it read. A nil ConfigMap means it does not exist yet.
func (s *Store) load(ctx context.Context) (map[string]string, *corev1.ConfigMap, error) {
	configMap := &corev1.ConfigMap{}
	err := s.Client.Get(ctx, s.objectKey(), configMap)
	if apierrors.IsNotFound(err) {
		return map[string]string{}, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read ownership store %s: %w", s.objectKey(), err)
	}
	state, err := decodeState(configMap)
	if err != nil {
		return nil, nil, err
	}
	return state, configMap, nil
}

// decodeState decodes the ConfigMap payload. An empty payload is an empty map,
// which is what a freshly created ConfigMap carries.
func decodeState(configMap *corev1.ConfigMap) (map[string]string, error) {
	raw := configMap.Data[StoreStateKey]
	if raw == "" {
		return map[string]string{}, nil
	}
	state := make(map[string]string)
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return nil, fmt.Errorf("decode ownership store %s/%s: %w", configMap.Namespace, configMap.Name, err)
	}
	return state, nil
}

// objectKey identifies the backing ConfigMap.
func (s *Store) objectKey() types.NamespacedName {
	return types.NamespacedName{Namespace: s.Namespace, Name: s.Name}
}
