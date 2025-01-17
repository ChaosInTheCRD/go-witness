// Copyright 2022 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cryptoutil

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
)

var (
	hashNames = map[DigestValue]string{
		{
			Hash:   crypto.SHA256,
			GitOID: false,
		}: "sha256",
		{
			Hash:   crypto.SHA1,
			GitOID: false,
		}: "sha1",
		{
			Hash:   crypto.SHA256,
			GitOID: true,
		}: "gitoid:sha256",
		{
			Hash:   crypto.SHA1,
			GitOID: true,
		}: "gitoid:sha1",
	}

	hashesByName = map[string]DigestValue{
		"sha256": {
			crypto.SHA256,
			false,
		},
		"sha1": {
			crypto.SHA1,
			false,
		},
		"gitoid:sha256": {
			crypto.SHA256,
			true,
		},
		"gitoid:sha1": {
			crypto.SHA1,
			true,
		},
	}
)

type ErrUnsupportedHash string

func (e ErrUnsupportedHash) Error() string {
	return fmt.Sprintf("unsupported hash function: %v", string(e))
}

type DigestValue struct {
	crypto.Hash
	GitOID bool
}

type DigestSet map[DigestValue]string

func HashToString(h crypto.Hash) (string, error) {
	if name, ok := hashNames[DigestValue{Hash: h}]; ok {
		return name, nil
	}

	return "", ErrUnsupportedHash(h.String())
}

func HashFromString(name string) (crypto.Hash, error) {
	if hash, ok := hashesByName[name]; ok {
		return hash.Hash, nil
	}

	return crypto.Hash(0), ErrUnsupportedHash(name)
}

// Equal returns true if every digest for hash functions both artifacts have in common are equal.
// If the two artifacts don't have any digests from common hash functions, equal will return false.
// If any digest from common hash functions differ between the two artifacts, equal will return false.
func (ds *DigestSet) Equal(second DigestSet) bool {
	hasMatchingDigest := false
	for hash, digest := range *ds {
		otherDigest, ok := second[hash]
		if !ok {
			continue
		}

		if digest == otherDigest {
			hasMatchingDigest = true
		} else {
			return false
		}
	}

	return hasMatchingDigest
}

func (ds *DigestSet) ToNameMap() (map[string]string, error) {
	nameMap := make(map[string]string)
	for hash, digest := range *ds {
		name, ok := hashNames[hash]
		if !ok {
			return nameMap, ErrUnsupportedHash(hash.String())
		}

		nameMap[name] = digest
	}

	return nameMap, nil
}

func NewDigestSet(digestsByName map[string]string) (DigestSet, error) {
	ds := make(DigestSet)
	for hashName, digest := range digestsByName {
		hash, ok := hashesByName[hashName]
		if !ok {
			return ds, ErrUnsupportedHash(hashName)
		}

		ds[hash] = digest
	}

	return ds, nil
}

func CalculateDigestSet(r io.Reader, hashes []crypto.Hash) (DigestSet, error) {
	digestSet := make(DigestSet)
	writers := []io.Writer{}
	hashfuncs := map[crypto.Hash]hash.Hash{}
	for _, hash := range hashes {
		hashfunc := hash.New()
		hashfuncs[hash] = hashfunc
		writers = append(writers, hashfunc)
	}

	multiwriter := io.MultiWriter(writers...)
	if _, err := io.Copy(multiwriter, r); err != nil {
		return digestSet, err
	}

	for hash, hashfunc := range hashfuncs {
		digestValue := DigestValue{
			Hash:   hash,
			GitOID: false,
		}
		digestSet[digestValue] = string(HexEncode(hashfunc.Sum(nil)))
	}
	return digestSet, nil
}

func CalculateDigestSetFromBytes(data []byte, hashes []crypto.Hash) (DigestSet, error) {
	return CalculateDigestSet(bytes.NewReader(data), hashes)
}

func CalculateDigestSetFromFile(path string, hashes []crypto.Hash) (DigestSet, error) {
	file, err := os.Open(path)
	if err != nil {
		return DigestSet{}, err
	}

	hashable, err := isHashableFile(file)
	if err != nil {
		return DigestSet{}, err
	}

	if !hashable {
		return DigestSet{}, fmt.Errorf("%s is not a hashable file", path)
	}

	defer file.Close()
	return CalculateDigestSet(file, hashes)
}

func (ds DigestSet) MarshalJSON() ([]byte, error) {
	nameMap, err := ds.ToNameMap()
	if err != nil {
		return nil, err
	}

	return json.Marshal(nameMap)
}

func (ds *DigestSet) UnmarshalJSON(data []byte) error {
	nameMap := make(map[string]string)
	err := json.Unmarshal(data, &nameMap)
	if err != nil {
		return err
	}

	newDs, err := NewDigestSet(nameMap)
	if err != nil {
		return err
	}

	*ds = newDs
	return nil
}

func isHashableFile(f *os.File) (bool, error) {
	stat, err := f.Stat()
	if err != nil {
		return false, err
	}

	mode := stat.Mode()

	isSpecial := stat.Mode()&os.ModeCharDevice != 0

	if isSpecial {
		return false, nil
	}

	if mode.IsRegular() {
		return true, nil
	}

	if mode.Perm().IsDir() {
		return true, nil
	}

	if mode&os.ModeSymlink == 1 {
		return true, nil
	}

	return false, nil
}
