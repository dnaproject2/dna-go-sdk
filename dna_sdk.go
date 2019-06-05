/*
 * Copyright (C) 2018 The dna Authors
 * This file is part of The dna library.
 *
 * The dna is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The dna is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with The dna.  If not, see <http://www.gnu.org/licenses/>.
 */

//Ontolog sdk in golang. Using for operation with dna
package dna_go_sdk

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"

	"github.com/ontio/ontology-crypto/keypair"
	"github.com/dnaproject2/dna-go-sdk/client"
	"github.com/dnaproject2/dna-go-sdk/utils"
	"github.com/dnaproject2/DNA/common"
	sign "github.com/dnaproject2/DNA/common"
	"github.com/dnaproject2/DNA/common/constants"
	"github.com/dnaproject2/DNA/core/payload"
	"github.com/dnaproject2/DNA/core/types"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

//DNASdk is the main struct for user
type DNASdk struct {
	client.ClientMgr
	Native *NativeContract
	NeoVM  *NeoVMContract
}

//NewDNASdk return DNASdk.
func NewDNASdk() *DNASdk {
	ontSdk := &DNASdk{}
	native := newNativeContract(ontSdk)
	ontSdk.Native = native
	neoVM := newNeoVMContract(ontSdk)
	ontSdk.NeoVM = neoVM
	return ontSdk
}

//CreateWallet return a new wallet
func (this *DNASdk) CreateWallet(walletFile string) (*Wallet, error) {
	if utils.IsFileExist(walletFile) {
		return nil, fmt.Errorf("wallet:%s has already exist", walletFile)
	}
	return NewWallet(walletFile), nil
}

//OpenWallet return a wallet instance
func (this *DNASdk) OpenWallet(walletFile string) (*Wallet, error) {
	return OpenWallet(walletFile)
}

//NewInvokeTransaction return smart contract invoke transaction
func (this *DNASdk) NewInvokeTransaction(gasPrice, gasLimit uint64, invokeCode []byte) *types.MutableTransaction {
	invokePayload := &payload.InvokeCode{
		Code: invokeCode,
	}
	tx := &types.MutableTransaction{
		GasPrice: gasPrice,
		GasLimit: gasLimit,
		TxType:   types.Invoke,
		Nonce:    rand.Uint32(),
		Payload:  invokePayload,
		Sigs:     make([]types.Sig, 0, 0),
	}
	return tx
}

func (this *DNASdk) SignToTransaction(tx *types.MutableTransaction, signer Signer) error {
	if tx.Payer == common.ADDRESS_EMPTY {
		account, ok := signer.(*Account)
		if ok {
			tx.Payer = account.Address
		}
	}
	for _, sigs := range tx.Sigs {
		if utils.PubKeysEqual([]keypair.PublicKey{signer.GetPublicKey()}, sigs.PubKeys) {
			//have already signed
			return nil
		}
	}
	txHash := tx.Hash()
	sigData, err := signer.Sign(txHash.ToArray())
	if err != nil {
		return fmt.Errorf("sign error:%s", err)
	}
	if tx.Sigs == nil {
		tx.Sigs = make([]types.Sig, 0)
	}
	tx.Sigs = append(tx.Sigs, types.Sig{
		PubKeys: []keypair.PublicKey{signer.GetPublicKey()},
		M:       1,
		SigData: [][]byte{sigData},
	})
	return nil
}

func (this *DNASdk) MultiSignToTransaction(tx *types.MutableTransaction, m uint16, pubKeys []keypair.PublicKey, signer Signer) error {
	pkSize := len(pubKeys)
	if m == 0 || int(m) > pkSize || pkSize > constants.MULTI_SIG_MAX_PUBKEY_SIZE {
		return fmt.Errorf("both m and number of pub key must larger than 0, and small than %d, and m must smaller than pub key number", constants.MULTI_SIG_MAX_PUBKEY_SIZE)
	}
	validPubKey := false
	for _, pk := range pubKeys {
		if keypair.ComparePublicKey(pk, signer.GetPublicKey()) {
			validPubKey = true
			break
		}
	}
	if !validPubKey {
		return fmt.Errorf("invalid signer")
	}
	if tx.Payer == common.ADDRESS_EMPTY {
		payer, err := types.AddressFromMultiPubKeys(pubKeys, int(m))
		if err != nil {
			return fmt.Errorf("AddressFromMultiPubKeys error:%s", err)
		}
		tx.Payer = payer
	}
	txHash := tx.Hash()
	if len(tx.Sigs) == 0 {
		tx.Sigs = make([]types.Sig, 0)
	}
	sigData, err := signer.Sign(txHash.ToArray())
	if err != nil {
		return fmt.Errorf("sign error:%s", err)
	}
	hasMutilSig := false
	for i, sigs := range tx.Sigs {
		if utils.PubKeysEqual(sigs.PubKeys, pubKeys) {
			hasMutilSig = true
			if utils.HasAlreadySig(txHash.ToArray(), signer.GetPublicKey(), sigs.SigData) {
				break
			}
			sigs.SigData = append(sigs.SigData, sigData)
			tx.Sigs[i] = sigs
			break
		}
	}
	if !hasMutilSig {
		tx.Sigs = append(tx.Sigs, types.Sig{
			PubKeys: pubKeys,
			M:       m,
			SigData: [][]byte{sigData},
		})
	}
	return nil
}

func (this *DNASdk) GetTxData(tx *types.MutableTransaction) (string, error) {
	txData, err := tx.IntoImmutable()
	if err != nil {
		return "", fmt.Errorf("IntoImmutable error:%s", err)
	}
	sink := sign.ZeroCopySink{}
	txData.Serialization(&sink)
	rawtx := hex.EncodeToString(sink.Bytes())
	return rawtx, nil
}

func (this *DNASdk) GetMutableTx(rawTx string) (*types.MutableTransaction, error) {
	txData, err := hex.DecodeString(rawTx)
	if err != nil {
		return nil, fmt.Errorf("RawTx hex decode error:%s", err)
	}
	tx, err := types.TransactionFromRawBytes(txData)
	if err != nil {
		return nil, fmt.Errorf("TransactionFromRawBytes error:%s", err)
	}
	mutTx, err := tx.IntoMutable()
	if err != nil {
		return nil, fmt.Errorf("[ONT]IntoMutable error:%s", err)
	}
	return mutTx, nil
}

func (this *DNASdk) GetMultiAddr(pubkeys []keypair.PublicKey, m int) (string, error) {
	addr, err := types.AddressFromMultiPubKeys(pubkeys, m)
	if err != nil {
		return "", fmt.Errorf("GetMultiAddrs error:%s", err)
	}
	return addr.ToBase58(), nil
}

func (this *DNASdk) GetAdddrByPubKey(pubKey keypair.PublicKey) string {
	address := types.AddressFromPubKey(pubKey)
	return address.ToBase58()
}
