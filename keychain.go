// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"github.com/ipfs/go-datastore"
	"github.com/ipfs/go-datastore/query"
	"github.com/libp2p/go-libp2p/core/crypto"
	icrypto "github.com/project-illium/ilxd/crypto"
	"github.com/project-illium/ilxd/params"
	"github.com/project-illium/ilxd/repo"
	"github.com/project-illium/ilxd/types"
	"github.com/project-illium/walletlib/pb"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/pbkdf2"
	"google.golang.org/protobuf/proto"
	"io"
	"sync"
	"time"
)

var (
	ErrUninitializedKeychain = errors.New("keychain uninitialized")
	ErrEncryptedKeychain     = errors.New("keychain encrypted")
	ErrPublicOnlyKeychain    = errors.New("keychain public only")
	ErrPermissionDenied      = errors.New("permission denied")

	MockBasicUnlockScriptCommitment = bytes.Repeat([]byte{0xff}, 32)
)

const (
	// defaultKdfRounds is the number of rounds to use when generating the
	// encryption key. The greater this number is, the harder it is to
	// brute force the encryption key.
	defaultKdfRounds = 8192

	// defaultKeyLength is the encryption key length generated by pbkdf2.
	defaultKeyLength = 32
)

type Keychain struct {
	ds              repo.Datastore
	params          *params.NetworkParams
	unencryptedSeed []byte

	isEncrypted bool
	isPruned    bool
	mtx         sync.RWMutex
}

func NewKeychain(ds repo.Datastore, params *params.NetworkParams, mnemonic string) (*Keychain, error) {
	if err := ds.Put(context.Background(), datastore.NewKey(MnemonicSeedDatastoreKey), []byte(mnemonic)); err != nil {
		return nil, err
	}

	salt := make([]byte, 32)
	rand.Read(salt)
	if err := ds.Put(context.Background(), datastore.NewKey(KeyDatastoreSaltKey), salt); err != nil {
		return nil, err
	}

	if err := ds.Put(context.Background(), datastore.NewKey(WalletEncryptedDatastoreKey), []byte{0x00}); err != nil {
		return nil, err
	}

	seed := bip39.NewSeed(mnemonic, "")

	addr, unlockingScript, viewKey, err := newAddress(0, seed, params)
	if err != nil {
		return nil, err
	}

	serializedKey, err := crypto.MarshalPrivateKey(viewKey)
	if err != nil {
		return nil, err
	}

	scriptHash := unlockingScript.Hash()

	addrInfo := &pb.AddrInfo{
		Addr: addr.String(),
		UnlockingScript: &pb.UnlockingScript{
			ScriptCommitment: unlockingScript.ScriptCommitment,
			ScriptParams:     unlockingScript.ScriptParams,
		},
		ScriptHash:  scriptHash[:],
		ViewPrivKey: serializedKey,
		KeyIndex:    0,
	}

	ser, err := proto.Marshal(addrInfo)
	if err != nil {
		return nil, err
	}

	if err := ds.Put(context.Background(), datastore.NewKey(AddressDatastoreKeyPrefix+addr.String()), ser); err != nil {
		return nil, err
	}
	if err := ds.Put(context.Background(), datastore.NewKey(CurrentAddressIndexDatastoreKey), []byte(addr.String())); err != nil {
		return nil, err
	}
	if err := ds.Put(context.Background(), datastore.NewKey(ViewKeyIndexDatastoreKey+hex.EncodeToString(serializedKey)), []byte(addr.String())); err != nil {
		return nil, err
	}

	return &Keychain{
		ds:              ds,
		params:          params,
		isEncrypted:     false,
		unencryptedSeed: seed,
		mtx:             sync.RWMutex{},
	}, nil
}

func LoadKeychain(ds repo.Datastore, params *params.NetworkParams) (*Keychain, error) {
	_, err := ds.Get(context.Background(), datastore.NewKey(CurrentAddressIndexDatastoreKey))
	if err != nil {
		return nil, ErrUninitializedKeychain
	}

	encrypted, err := ds.Get(context.Background(), datastore.NewKey(WalletEncryptedDatastoreKey))
	if err != nil {
		return nil, err
	}

	pruned := false
	_, err = ds.Get(context.Background(), datastore.NewKey(MnemonicSeedDatastoreKey))
	if errors.Is(err, datastore.ErrNotFound) {
		pruned = true
	} else if err != nil {
		return nil, err
	}

	kc := &Keychain{
		ds:          ds,
		params:      params,
		isEncrypted: encrypted[0] == 0x01,
		isPruned:    pruned,
		mtx:         sync.RWMutex{},
	}

	if encrypted[0] == 0x00 && !pruned {
		mnemonic, err := kc.ds.Get(context.Background(), datastore.NewKey(MnemonicSeedDatastoreKey))
		if err != nil {
			return nil, err
		}
		kc.unencryptedSeed = bip39.NewSeed(string(mnemonic), "")
	}

	return kc, nil
}

func (kc *Keychain) Addresses() ([]Address, error) {
	kc.mtx.RLock()
	defer kc.mtx.RUnlock()

	results, err := kc.ds.Query(context.Background(), query.Query{
		Prefix: AddressDatastoreKeyPrefix,
	})
	if err != nil {
		return nil, err
	}
	addrs := make([]Address, 0, 5)
	for result, ok := results.NextSync(); ok; result, ok = results.NextSync() {
		var addrInfo pb.AddrInfo
		if err := proto.Unmarshal(result.Value, &addrInfo); err != nil {
			return nil, err
		}

		addr, err := DecodeAddress(addrInfo.Addr, kc.params)
		if err != nil {
			return nil, err
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

func (kc *Keychain) Address() (Address, error) {
	kc.mtx.RLock()
	defer kc.mtx.RUnlock()

	addrStr, err := kc.ds.Get(context.Background(), datastore.NewKey(CurrentAddressIndexDatastoreKey))
	if err != nil {
		return nil, err
	}

	return DecodeAddress(string(addrStr), kc.params)
}

func (kc *Keychain) NewAddress() (Address, error) {
	kc.mtx.Lock()
	defer kc.mtx.Unlock()

	if kc.isEncrypted {
		return nil, ErrEncryptedKeychain
	}
	if kc.isPruned {
		return nil, ErrPublicOnlyKeychain
	}

	addrStr, err := kc.ds.Get(context.Background(), datastore.NewKey(CurrentAddressIndexDatastoreKey))
	if err != nil {
		return nil, err
	}
	ser, err := kc.ds.Get(context.Background(), datastore.NewKey(AddressDatastoreKeyPrefix+string(addrStr)))
	if err != nil {
		return nil, err
	}

	var currentAddrInfo pb.AddrInfo
	if err := proto.Unmarshal(ser, &currentAddrInfo); err != nil {
		return nil, err
	}

	newIndex := currentAddrInfo.KeyIndex + 1

	addr, unlockingScript, viewKey, err := newAddress(newIndex, kc.unencryptedSeed, kc.params)
	if err != nil {
		return nil, err
	}
	scriptHash := unlockingScript.Hash()

	serializedKey, err := crypto.MarshalPrivateKey(viewKey)
	if err != nil {
		return nil, err
	}

	addrInfo := &pb.AddrInfo{
		Addr: addr.String(),
		UnlockingScript: &pb.UnlockingScript{
			ScriptCommitment: unlockingScript.ScriptCommitment,
			ScriptParams:     unlockingScript.ScriptParams,
		},
		ScriptHash:  scriptHash[:],
		ViewPrivKey: serializedKey,
		KeyIndex:    newIndex,
	}

	ser, err = proto.Marshal(addrInfo)
	if err != nil {
		return nil, err
	}

	if err := kc.ds.Put(context.Background(), datastore.NewKey(AddressDatastoreKeyPrefix+addr.String()), ser); err != nil {
		return nil, err
	}
	if err := kc.ds.Put(context.Background(), datastore.NewKey(CurrentAddressIndexDatastoreKey), []byte(addr.String())); err != nil {
		return nil, err
	}
	if err := kc.ds.Put(context.Background(), datastore.NewKey(ViewKeyIndexDatastoreKey+hex.EncodeToString(serializedKey)), []byte(addr.String())); err != nil {
		return nil, err
	}

	return addr, nil
}

func (kc *Keychain) PrivateKeys() (map[WalletPrivateKey]Address, error) {
	kc.mtx.RLock()
	defer kc.mtx.RUnlock()

	if kc.isEncrypted {
		return nil, ErrEncryptedKeychain
	}
	if kc.isPruned {
		return nil, ErrPublicOnlyKeychain
	}

	results, err := kc.ds.Query(context.Background(), query.Query{
		Prefix: AddressDatastoreKeyPrefix,
	})
	if err != nil {
		return nil, err
	}
	keys := make(map[WalletPrivateKey]Address)
	spendMaster, err := seedToSpendMaster(kc.unencryptedSeed)
	if err != nil {
		return nil, err
	}
	viewMaster, err := seedToViewMaster(kc.unencryptedSeed)
	if err != nil {
		return nil, err
	}
	for result, ok := results.NextSync(); ok; result, ok = results.NextSync() {
		var addrInfo pb.AddrInfo
		if err := proto.Unmarshal(result.Value, &addrInfo); err != nil {
			return nil, err
		}
		if addrInfo.WatchOnly {
			continue
		}
		addr, err := DecodeAddress(addrInfo.Addr, kc.params)
		if err != nil {
			return nil, err
		}

		childSpendKey, err := spendMaster.Child(addrInfo.KeyIndex)
		if err != nil {
			return nil, err
		}
		rawSpend, err := childSpendKey.Raw()
		if err != nil {
			return nil, err
		}
		childViewKey, err := viewMaster.Child(addrInfo.KeyIndex)
		if err != nil {
			return nil, err
		}
		rawView, err := childViewKey.Raw()
		if err != nil {
			return nil, err
		}
		k := WalletPrivateKey{}
		copy(k.spendKey[:], rawSpend[:32])
		copy(k.viewKey[:], rawView[:32])
		keys[k] = addr
	}
	return keys, nil
}

func (kc *Keychain) ImportAddress(addr Address, unlockingScript types.UnlockingScript, viewPrivkey crypto.PrivKey) error {
	kc.mtx.Lock()
	defer kc.mtx.Unlock()

	_, ok := viewPrivkey.(*icrypto.Curve25519PrivateKey)
	if !ok {
		return errors.New("view key is not curve25519")
	}

	serializedKey, err := crypto.MarshalPrivateKey(viewPrivkey)
	if err != nil {
		return err
	}

	_, err = kc.ds.Get(context.Background(), datastore.NewKey(ViewKeyIndexDatastoreKey+hex.EncodeToString(serializedKey)))
	if !errors.Is(err, datastore.ErrNotFound) {
		return errors.New("view key already exists in wallet")
	}

	scriptHash := unlockingScript.Hash()

	addrInfo := &pb.AddrInfo{
		Addr: addr.String(),
		UnlockingScript: &pb.UnlockingScript{
			ScriptCommitment: unlockingScript.ScriptCommitment,
			ScriptParams:     unlockingScript.ScriptParams,
		},
		ScriptHash:  scriptHash[:],
		ViewPrivKey: serializedKey,
		WatchOnly:   true,
	}

	ser, err := proto.Marshal(addrInfo)
	if err != nil {
		return err
	}

	if err := kc.ds.Put(context.Background(), datastore.NewKey(ViewKeyIndexDatastoreKey+hex.EncodeToString(serializedKey)), []byte(addr.String())); err != nil {
		return err
	}

	return kc.ds.Put(context.Background(), datastore.NewKey(AddressDatastoreKeyPrefix+addr.String()), ser)
}

func (kc *Keychain) NetworkKey() (crypto.PrivKey, error) {
	kc.mtx.RLock()
	defer kc.mtx.RUnlock()

	if kc.isEncrypted {
		return nil, ErrEncryptedKeychain
	}
	if kc.isPruned {
		return nil, ErrPublicOnlyKeychain
	}

	return seedToNetworkKey(kc.unencryptedSeed)
}

func (kc *Keychain) spendKey(index uint32) (crypto.PrivKey, error) {
	kc.mtx.RLock()
	defer kc.mtx.RUnlock()

	if kc.isEncrypted {
		return nil, ErrEncryptedKeychain
	}
	if kc.isPruned {
		return nil, ErrPublicOnlyKeychain
	}

	spendMaster, err := seedToSpendMaster(kc.unencryptedSeed)
	if err != nil {
		return nil, err
	}

	hdkey, err := spendMaster.Child(index)
	if err != nil {
		return nil, err
	}
	return hdkey.PrivKey, nil
}

func (kc *Keychain) addrInfo(viewKey crypto.PrivKey) (*pb.AddrInfo, error) {
	serializedKey, err := crypto.MarshalPrivateKey(viewKey)
	if err != nil {
		return nil, err
	}
	addrStr, err := kc.ds.Get(context.Background(), datastore.NewKey(ViewKeyIndexDatastoreKey+hex.EncodeToString(serializedKey)))
	if err != nil {
		return nil, err
	}
	ser, err := kc.ds.Get(context.Background(), datastore.NewKey(AddressDatastoreKeyPrefix+string(addrStr)))
	if err != nil {
		return nil, err
	}
	var addrInfo pb.AddrInfo
	if err := proto.Unmarshal(ser, &addrInfo); err != nil {
		return nil, err
	}
	return &addrInfo, nil
}

func newAddress(index uint32, seed []byte, params *params.NetworkParams) (Address, types.UnlockingScript, *icrypto.Curve25519PrivateKey, error) {
	spendMaster, err := seedToSpendMaster(seed)
	if err != nil {
		return nil, types.UnlockingScript{}, nil, err
	}
	childSpendKey, err := spendMaster.Child(index)
	if err != nil {
		return nil, types.UnlockingScript{}, nil, err
	}
	rawPublic, err := childSpendKey.GetPublic().Raw()
	if err != nil {
		return nil, types.UnlockingScript{}, nil, err
	}

	viewMaster, err := seedToViewMaster(seed)
	if err != nil {
		return nil, types.UnlockingScript{}, nil, err
	}
	childViewKey, err := viewMaster.Child(index)
	if err != nil {
		return nil, types.UnlockingScript{}, nil, err
	}

	script := types.UnlockingScript{
		ScriptCommitment: MockBasicUnlockScriptCommitment,
		ScriptParams:     [][]byte{rawPublic},
	}

	addr, err := NewBasicAddress(script, childViewKey.PrivateKey().GetPublic(), params)
	return addr, script, childViewKey.PrivateKey().(*icrypto.Curve25519PrivateKey), err
}

func (kc *Keychain) SetPassphrase(passphrase string) error {
	kc.mtx.Lock()
	defer kc.mtx.Unlock()

	encrypted, err := kc.ds.Get(context.Background(), datastore.NewKey(WalletEncryptedDatastoreKey))
	if err != nil {
		return err
	}
	if encrypted[0] == 0x01 {
		return errors.New("wallet already encrypted")
	}

	salt, err := kc.ds.Get(context.Background(), datastore.NewKey(KeyDatastoreSaltKey))
	if err != nil {
		return err
	}

	mnemonic, err := kc.ds.Get(context.Background(), datastore.NewKey(MnemonicSeedDatastoreKey))
	if err != nil {
		return err
	}

	dk := pbkdf2.Key([]byte(passphrase), salt, defaultKdfRounds, defaultKeyLength, sha512.New)

	block, err := aes.NewCipher(dk)
	if err != nil {
		return err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(mnemonic))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], mnemonic)

	if err := kc.ds.Put(context.Background(), datastore.NewKey(MnemonicSeedDatastoreKey), mnemonic); err != nil {
		return err
	}

	if err := kc.ds.Put(context.Background(), datastore.NewKey(WalletEncryptedDatastoreKey), []byte{0x01}); err != nil {
		return err
	}

	h := sha256.Sum256(dk)
	if err := kc.ds.Put(context.Background(), datastore.NewKey(PassphraseHashDatastoreKey), h[:]); err != nil {
		return err
	}

	kc.isEncrypted = true
	return nil
}

func (kc *Keychain) ChangePassphrase(currentPassphrase, newPassphrase string) error {
	encrypted, err := kc.ds.Get(context.Background(), datastore.NewKey(WalletEncryptedDatastoreKey))
	if err != nil {
		return err
	}
	if encrypted[0] == 0x00 {
		return errors.New("wallet not encrypted")
	}

	ciphertext, err := kc.ds.Get(context.Background(), datastore.NewKey(MnemonicSeedDatastoreKey))
	if err != nil {
		return err
	}

	salt, err := kc.ds.Get(context.Background(), datastore.NewKey(KeyDatastoreSaltKey))
	if err != nil {
		return err
	}

	dk := pbkdf2.Key([]byte(currentPassphrase), salt, defaultKdfRounds, defaultKeyLength, sha512.New)

	h, err := kc.ds.Get(context.Background(), datastore.NewKey(PassphraseHashDatastoreKey))
	if err != nil {
		return err
	}
	pkh := sha256.Sum256(dk)
	if !bytes.Equal(pkh[:], h) {
		return ErrPermissionDenied
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		return err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		return errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	dk2 := pbkdf2.Key([]byte(newPassphrase), salt, defaultKdfRounds, defaultKeyLength, sha512.New)

	block2, err := aes.NewCipher(dk2)
	if err != nil {
		return err
	}

	// The IV needs to be unique, but not secure. Therefor it's common to
	// include it at the beginning of the ciphertext.
	ciphertext2 := make([]byte, aes.BlockSize+len(ciphertext))
	iv = ciphertext2[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	stream = cipher.NewCFBEncrypter(block2, iv)
	stream.XORKeyStream(ciphertext2[aes.BlockSize:], ciphertext)

	pkh2 := sha256.Sum256(dk2)
	if err := kc.ds.Put(context.Background(), datastore.NewKey(PassphraseHashDatastoreKey), pkh2[:]); err != nil {
		return err
	}

	return kc.ds.Put(context.Background(), datastore.NewKey(MnemonicSeedDatastoreKey), []byte(ciphertext))
}

func (kc *Keychain) Unlock(passphrase string, duration time.Duration) error {
	kc.mtx.Lock()
	defer kc.mtx.Unlock()

	if !kc.isEncrypted {
		return errors.New("keychain already unlocked")
	}

	ciphertext, err := kc.ds.Get(context.Background(), datastore.NewKey(MnemonicSeedDatastoreKey))
	if err != nil {
		return err
	}

	salt, err := kc.ds.Get(context.Background(), datastore.NewKey(KeyDatastoreSaltKey))
	if err != nil {
		return err
	}

	dk := pbkdf2.Key([]byte(passphrase), salt, defaultKdfRounds, defaultKeyLength, sha512.New)
	h, err := kc.ds.Get(context.Background(), datastore.NewKey(PassphraseHashDatastoreKey))
	if err != nil {
		return err
	}
	pkh := sha256.Sum256(dk)
	if !bytes.Equal(pkh[:], h) {
		return ErrPermissionDenied
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		return err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		return errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	seed := bip39.NewSeed(string(ciphertext), "")

	kc.unencryptedSeed = seed
	kc.isEncrypted = false
	time.AfterFunc(duration, func() {
		kc.mtx.Lock()
		kc.isEncrypted = true
		kc.unencryptedSeed = nil
		kc.mtx.Unlock()
	})
	return nil
}

func (kc *Keychain) Lock() error {
	kc.mtx.Lock()
	defer kc.mtx.Unlock()

	encrypted, err := kc.ds.Get(context.Background(), datastore.NewKey(WalletEncryptedDatastoreKey))
	if err != nil {
		return err
	}
	if encrypted[0] == 0x00 {
		return errors.New("wallet not encrypted, use setpassphrase first")
	}

	if kc.isEncrypted {
		return errors.New("wallet is already locked")
	}

	kc.isEncrypted = true
	kc.unencryptedSeed = nil
	return nil
}

func (kc *Keychain) Prune() error {
	kc.mtx.Lock()
	defer kc.mtx.Unlock()

	if kc.isEncrypted {
		return ErrEncryptedKeychain
	}
	if err := kc.ds.Delete(context.Background(), datastore.NewKey(MnemonicSeedDatastoreKey)); err != nil {
		return err
	}

	kc.isPruned = true
	return nil
}

func (kc *Keychain) getViewKeys() ([]*icrypto.Curve25519PrivateKey, error) {
	kc.mtx.RLock()
	defer kc.mtx.RUnlock()

	viewKeys := make([]*icrypto.Curve25519PrivateKey, 0, 1)
	results, err := kc.ds.Query(context.Background(), query.Query{
		Prefix: AddressDatastoreKeyPrefix,
	})
	if err != nil {
		return nil, err
	}
	for result, ok := results.NextSync(); ok; result, ok = results.NextSync() {
		var addrInfo pb.AddrInfo
		if err := proto.Unmarshal(result.Value, &addrInfo); err != nil {
			return nil, err
		}

		privKey, err := crypto.UnmarshalPrivateKey(addrInfo.ViewPrivKey)
		if err != nil {
			return nil, err
		}
		viewKey, ok := privKey.(*icrypto.Curve25519PrivateKey)
		if !ok {
			return nil, errors.New("error decoding key")
		}

		viewKeys = append(viewKeys, viewKey)
	}
	return viewKeys, nil
}
