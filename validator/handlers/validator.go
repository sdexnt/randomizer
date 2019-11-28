package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strings"
	"time"

	//"github.com/gogo/protobuf/proto"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/common/flogging"
	validation "github.com/hyperledger/fabric/core/handlers/validation/api"
	"github.com/hyperledger/fabric/core/peer"

	"github.com/hyperledger/fabric/gossip/api"
	"github.com/hyperledger/fabric/gossip/common"
	"github.com/hyperledger/fabric/gossip/service"

	"github.com/hyperledger/fabric/common/channelconfig"

	cb "github.com/hyperledger/fabric/protos/common"
	pmsp "github.com/hyperledger/fabric/protos/msp"
	pb "github.com/hyperledger/fabric/protos/peer"
	"github.com/hyperledger/fabric/protos/utils"

	"github.com/pkg/errors"
)

var logger = flogging.MustGetLogger("customValidator")

const timedelta = 30

type sortedPeers []peerInfo

func (sp sortedPeers) Len() int      { return len(sp) }
func (sp sortedPeers) Swap(i, j int) { sp[i], sp[j] = sp[j], sp[i] }
func (sp sortedPeers) Less(i, j int) bool {
	left := strings.ToLower(sp[i].Address)
	right := strings.ToLower(sp[j].Address)
	return left < right
}

// Argument defines the argument for validation
type Argument interface {
	validation.Dependency
	Arg() []byte
}

// Dependency marks a dependency passed to the Init() method
//type Dependency interface{}

// ContextDatum defines additional data that is passed from the validator
// into the Validate() invocation
//type ContextDatum interface{}

// CustomValidator is used to test validation plugin infrastructure
type CustomValidator struct {
}

type peerInfo struct {
	Address   string
	PKIid     common.PKIidType
	Identity  []byte
	PublicKey []byte
}

type PeersGroup struct {
	mspID string
	peers []peerInfo
}

type PeerIdentitySet []api.PeerIdentityInfo

func getPeersByOrgs(channelId string) ([]PeersGroup, error) {

	var peersGroups []PeersGroup

	gss := service.GetGossipService()
	if gss == nil {
		fmt.Println("GossipService is nil")
		return nil, errors.New("GossipService is nil")
	}

	currPeer := gss.SelfMembershipInfo()

	channelPeers := gss.PeersOfChannel([]byte(channelId))
	channelPeers = append(channelPeers, currPeer)

	fmt.Println("channels peers:")
	for ind, peer := range channelPeers {

		fmt.Printf("  %d. endpoint: %s\n", ind, peer.Endpoint)
	}

	peersSet := gss.IdentityInfo()

	for key, orgPeers := range peersSet.ByOrg() {
		group := PeersGroup{}
		group.mspID = key
		for _, peer := range orgPeers {
			for _, channelPeer := range channelPeers {
				if peer.PKIId.String() == channelPeer.PKIid.String() {
					pinfo := peerInfo{}
					pinfo.PKIid = channelPeer.PKIid
					pinfo.Address = channelPeer.Endpoint
					pinfo.Identity = peer.Identity
					group.peers = append(group.peers, pinfo)
					break
				}
			}
		}
		peersGroups = append(peersGroups, group)
	}

	return peersGroups, nil
}

func getEndorsersFromConfigBlock(chainId string, num uint64) ([]PeersGroup, error) {

	cfgBlock, err := peer.GetLedger(chainId).GetBlockByNumber(num)

	// begin new test
	envelopeConfig, err := utils.ExtractEnvelope(cfgBlock, 0)
	if err != nil {
		return nil, errors.Errorf("Failed to %s", err)
	}

	configEnv := &cb.ConfigEnvelope{}
	_, err = utils.UnmarshalEnvelopeOfType(envelopeConfig, cb.HeaderType_CONFIG, configEnv)
	if err != nil {
		return nil, errors.Errorf("Bad configuration envelope: %s", err)
	}

	appGroup, exists := configEnv.Config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey]
	if !exists {
		return nil, errors.Errorf("Invalid configuration block, missing %s "+
			"configuration group", channelconfig.ApplicationGroupKey)
	}

	for key, group := range appGroup.Groups {
		fmt.Printf("key %s   group: %s\n", key, group.String())
	}

	var peersGroups []PeersGroup

	return peersGroups, nil

}

// Validate valides the transactions with the given data
func (*CustomValidator) Validate(block *cb.Block, namespace string, txPosition int, actionPosition int, _ ...validation.ContextDatum) error {

	fmt.Println("CustomValidator.Validate() begin")

	var err error

	chainId, err := utils.GetChainIDFromBlock(block)
	if err != nil {
		return err
	}

	lastConfBlock, err := utils.GetLastConfigIndexFromBlock(block)
	if err != nil {
		return err
	}
	fmt.Printf("lastConfigBlockIndex: %d\n", lastConfBlock)

	// begin new test

	res := peer.GetStableChannelConfig(chainId)
	if res == nil {
		return nil
	}
	appConfig, ok := res.ApplicationConfig()
	if !ok {
		return nil
	}

	//defAppConfig, ok := peer.DefaultSupport.GetApplicationConfig(chainId)
	//if !ok {
	//	return nil
	//}

	var peersGroups []PeersGroup
	var sp sortedPeers

	for key, org := range appConfig.Organizations() {
		group := PeersGroup{}
		group.mspID = key
		fmt.Printf("endorsers for %s\n", key)
		for ind, endorser := range org.Endorsers() {
			pinfo := peerInfo{}
			pinfo.Address = endorser.Address
			group.peers = append(group.peers, pinfo)
			fmt.Printf("   %d. %s\n", ind, endorser.Address)
		}
		peersGroups = append(peersGroups, group)
	}

	for ind := range peersGroups {
		sp = peersGroups[ind].peers
		sort.Sort(sp)
		peersGroups[ind].peers = sp
	}

	/************ begin test ************/

	//fmt.Println("after sorting")
	//for _, group := range peersGroups {
	//	fmt.Printf("group: %s\n", group.mspID)
	//	for ind, peer := range group.peers {
	//		fmt.Printf("  %d. peer address: %s\n", ind, peer.Address)
	//	}
	//}

	/************* end test *************/

	fmt.Println("Block info:")
	fmt.Printf("  number  : %d\n", block.Header.Number)
	fmt.Printf("  prevHash: %v\n", block.Header.PreviousHash)
	//fmt.Printf("  currHash: %v\n", block.Header.DataHash)
	//fmt.Printf("Namespace : %v\n", namespace)
	//fmt.Printf("TxPosition    : %d\n", txPosition)
	//fmt.Printf("ActionPosition: %d\n", actionPosition)

	data := block.GetData()
	if data == nil {
		return errors.New("error: block data is nil")
	}

	env := &cb.Envelope{}
	err = proto.Unmarshal(data.Data[txPosition], env)
	if err != nil {
		return err
	}

	payload, err := utils.UnmarshalPayload(env.Payload)
	if err != nil {
		return err
	}

	channelHeader, err := utils.UnmarshalChannelHeader(payload.Header.ChannelHeader)
	if err != nil {
		return err
	}

	fmt.Printf("time now: %d\n", time.Now().Unix())
	fmt.Printf("time tx: %d\n", channelHeader.Timestamp.GetSeconds())
	tmNow := float64(time.Now().Unix())
	tmTx := float64(channelHeader.Timestamp.GetSeconds())
	if math.Abs(tmNow-tmTx) > float64(timedelta) {
		return errors.New("block validating is time out")
	}

	tx, err := utils.GetTransaction(payload.Data)
	if err != nil {
		return err
	}
	txHdr, err := utils.GetSignatureHeader(tx.Actions[actionPosition].Header)
	if err != nil {
		return err
	}

	identity := &pmsp.SerializedIdentity{}
	err = proto.Unmarshal(txHdr.Creator, identity)
	if err != nil {
		return err
	}
	crtBytes, _ := pem.Decode(identity.IdBytes)
	certificate, err := x509.ParseCertificate(crtBytes.Bytes)
	if err != nil {
		return err
	}

	fmt.Printf("Creator mspID: %s\n", identity.Mspid)
	fmt.Printf("Creator cert : %s\n", certificate.Subject)
	fmt.Printf("RawSubjectPublicKeyInfo: %v\n", certificate.RawSubjectPublicKeyInfo)
	//certificate.Signature

	var rndmInit []byte
	var selectedPeers []peerInfo

	rndmInit = append(rndmInit, block.Header.PreviousHash...)
	rndmInit = append(rndmInit, []byte(string(block.Header.Number))...)
	rndmInit = append(rndmInit, certificate.RawSubjectPublicKeyInfo...)
	fmt.Printf("rndmInit: %v\n", rndmInit)

	for _, group := range peersGroups {
		rndmInd, err := rand.Int(bytes.NewBuffer(rndmInit), big.NewInt(int64(len(group.peers))))
		if err != nil {
			return err
		}
		index := int(rndmInd.Int64())
		if index >= len(group.peers) {
			index = len(group.peers) - 1
		}
		selectedPeers = append(selectedPeers, group.peers[index])
	}

	fmt.Println("selected peers:")
	for ind, peer := range selectedPeers {

		fmt.Printf("  %d. Address  : %s\n", ind, peer.Address)
		//fmt.Printf("  %d. PKIid    : %s\n", ind, peer.PKIid.String())

		//err = proto.Unmarshal(peer.Identity, identity)
		//if err != nil {
		//	return err
		//}
		//crtBytes, _ := pem.Decode(identity.IdBytes)
		//certificate, err := x509.ParseCertificate(crtBytes.Bytes)
		//if err != nil {
		//	return err
		//}

		//selectedPeers[ind].PublicKey = certificate.RawSubjectPublicKeyInfo
		//fmt.Printf("  %d. Cert      : %s\n", ind, certificate.Subject.String())
		//fmt.Printf("  %d. Public Key: %v\n", ind, certificate.RawSubjectPublicKeyInfo)
	}

	txPayload, err := utils.GetChaincodeActionPayload(tx.Actions[actionPosition].Payload)
	if err != nil {
		return err
	}

	proposalPayload, err := utils.GetChaincodeProposalPayload(txPayload.ChaincodeProposalPayload)
	if err != nil {
		return err
	}

	spec := &pb.ChaincodeInvocationSpec{}
	err = proto.Unmarshal(proposalPayload.Input, spec)
	if err != nil {
		return err
	}

	fmt.Printf("Chaincode type: %s\n", spec.ChaincodeSpec.Type.String())

	//if len(txPayload.Action.Endorsements) != len(selectedPeers) {
	//	return errors.New(fmt.Sprintf("wrong count of endorsers in block: wanted %d, got %d", len(selectedPeers), len(txPayload.Action.Endorsements)))
	//}

	//var found bool

	for ind, endorsement := range txPayload.Action.Endorsements {
		err = proto.Unmarshal(endorsement.Endorser, identity)
		if err != nil {
			return err
		}
		crtBytes, _ := pem.Decode(identity.IdBytes)
		fmt.Println("crt block headers:")
		for key, val := range crtBytes.Headers {
			fmt.Printf("  key: %s, value: %s\n", key, val)
		}
		fmt.Printf("crt block type: %s\n", crtBytes.Type)

		certificate, err := x509.ParseCertificate(crtBytes.Bytes)
		if err != nil {
			return err
		}

		fmt.Printf("Endorser %d:\n", ind)
		fmt.Printf("  MSP           : %s\n", identity.Mspid)
		fmt.Printf("  Cert CN       : %v\n", certificate.Subject.CommonName)
		//fmt.Printf("  KeyId         : %v\n", certificate.SubjectKeyId)
		//fmt.Printf("  Cert Sign     : %s\n", hex.EncodeToString(certificate.Signature))
		fmt.Printf("  Raw Public Key: %v\n", certificate.RawSubjectPublicKeyInfo)
		//fmt.Printf("  AuthorityKeyId: %s\n", hex.EncodeToString(certificate.AuthorityKeyId))
		//fmt.Printf("  Signature     : %v\n", endorsement.Signature)

		//found = false
		//for _, selectedPeer := range selectedPeers {
		//	if bytes.Compare(selectedPeer.PublicKey, certificate.RawSubjectPublicKeyInfo) == 0 {
		//		found = true
		//		fmt.Printf("endorser %s is valid\n", selectedPeer.Address)
		//		break
		//	}
		//}
		//if !found {
		//	return errors.New(fmt.Sprintf("endorser %s is not found"))
		//}
	}

	//hash(hash(Block)||Seq||Pkey)

	fmt.Println("CustomValidator.Validate() end")
	return nil
}

// Init initializes the plugin with the given dependencies
func (*CustomValidator) Init(dependencies ...validation.Dependency) error {
	logger.Infof("logger: CustomValidator.Init()")
	return nil
}

// CustomValidatorFactory creates new CustomValidators
type CustomValidatorFactory struct {
}

// New returns an instance of a CustomValidator
func (*CustomValidatorFactory) New() validation.Plugin {
	logger.Infof("logger: CustomValidatorFactory.New()")
	return &CustomValidator{}
}

func NewPluginFactory() validation.PluginFactory {
	logger.Infof("logger: create CustomValidatorFactory")
	return &CustomValidatorFactory{}
}

// ExecutionFailureError indicates that the validation
// failed because of an execution problem, and thus
// the transaction validation status could not be computed
//type ExecutionFailureError struct {
//	Reason string
//}

// Error conveys this is an error, and also contains
// the reason for the error
//func (e *ExecutionFailureError) Error() string {
//	return e.Reason
//}

/*

type PolicyEvaluator struct {
	msp.IdentityDeserializer
}

// Evaluate takes a set of SignedData and evaluates whether this set of signatures satisfies the policy
func (id *PolicyEvaluator) Evaluate(policyBytes []byte, signatureSet []*cb.SignedData) error {
	pp := cauthdsl.NewPolicyProvider(id.IdentityDeserializer)
	policy, _, err := pp.NewPolicy(policyBytes)
	if err != nil {
		return err
	}
	return policy.Evaluate(signatureSet)
}

// DeserializeIdentity unmarshals the given identity to msp.Identity
func (id *PolicyEvaluator) DeserializeIdentity(serializedIdentity []byte) (Identity, error) {
	mspIdentity, err := id.IdentityDeserializer.DeserializeIdentity(serializedIdentity)
	if err != nil {
		return nil, err
	}
	return &identity{Identity: mspIdentity}, nil
}

type identity struct {
	msp.Identity
}

func (i *identity) GetIdentityIdentifier() *IdentityIdentifier {
	identifier := i.Identity.GetIdentifier()
	return &IdentityIdentifier{
		Id:    identifier.Id,
		Mspid: identifier.Mspid,
	}
}

*/
