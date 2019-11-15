package customselection

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	contextImpl "github.com/hyperledger/fabric-sdk-go/pkg/context"
	"github.com/hyperledger/fabric-sdk-go/pkg/util/concurrent/lazycache"
	"github.com/hyperledger/fabric-sdk-go/pkg/util/concurrent/lazyref"

	"github.com/hyperledger/fabric-sdk-go/pkg/client/ledger"
	copts "github.com/hyperledger/fabric-sdk-go/pkg/common/options"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/context"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/pkg/errors"

	"github.com/hyperledger/fabric-sdk-go/pkg/client/common/selection/dynamicselection/pgresolver"
)

const defaultCacheTimeout = 30 * time.Minute

// Opt applies a selection provider option
type Opt func(*SelectionService)

type PeersGroup struct {
	mspID string
	peers []*fab.Peer
}

type EndorsingPeer struct {
	mspID string
	name  string
	url   string

	fab.ProposalProcessor
}

func (ep *EndorsingPeer) MSPID() string { return ep.mspID }
func (ep *EndorsingPeer) URL() string   { return ep.url }
func (ep *EndorsingPeer) Name() string  { return ep.name }

type sortedPeers []*EndorsingPeer

func (sp sortedPeers) Len() int      { return len(sp) }
func (sp sortedPeers) Swap(i, j int) { sp[i], sp[j] = sp[j], sp[i] }
func (sp sortedPeers) Less(i, j int) bool {
	left := strings.ToLower(sp[i].Name())
	right := strings.ToLower(sp[j].Name())
	return left < right
}

type Algorithm interface {
	//selectEndorsers(ctx context.Client, channelID string) ([]fab.Peer, error)
	selectEndorsers(ctx context.Client, channelID string) ([]*EndorsingPeer, error)
}

type algorithmImpl struct {
	endorsers Algorithm
}

//func (alg *algorithmImpl) selectEndorsers(ctx context.Client, channelID string) ([]fab.Peer, error) {
func (alg *algorithmImpl) selectEndorsers(ctx context.Client, channelID string) ([]*EndorsingPeer, error) {

	var peers []*EndorsingPeer

	channelCtx := getChannelContext(ctx, channelID)

	ledgerClient, err := ledger.New(channelCtx)
	if err != nil {
		return peers, err
	}

	resp, err := ledgerClient.QueryInfo()
	if err != nil {
		return peers, err
	}
	fmt.Printf("block height: %d\n", resp.BCI.Height)
	fmt.Printf("cur block hash: %v\n", resp.BCI.CurrentBlockHash)
	fmt.Printf("prev block hash: %v\n", resp.BCI.PreviousBlockHash)

	key, err := ctx.PrivateKey().PublicKey()
	pubKey, err := key.Bytes()
	fmt.Printf("public key: %v\n", pubKey)

	var rndmInit []byte
	rndmInit = append(rndmInit, resp.BCI.CurrentBlockHash...)
	rndmInit = append(rndmInit, []byte(string(resp.BCI.Height))...)
	rndmInit = append(rndmInit, pubKey...)
	fmt.Printf("rndmInit: %v\n", rndmInit)

	/*************** begin test ***************/

	//chPeers := ctx.EndpointConfig().ChannelPeers("mychannel")
	//for _, peer := range chPeers {
	//	fmt.Printf("chPeers URL: %s\n", peer.URL)
	//	if str, ok := peer.NetworkPeer.GRPCOptions["ssl-target-name-override"].(string); ok {
	//		fmt.Printf("chPeers NetworkPeer.Name: %s\n", str)
	//	}
	//}

	cfg, err := ledgerClient.QueryConfig()
	if err != nil {
		return peers, err
	}

	endorsersByGroups := make(map[string][]*EndorsingPeer)
	for _, endorser := range cfg.Endorsers() {
		group := endorsersByGroups[endorser.Org]
		peer := &EndorsingPeer{}
		peer.mspID = endorser.Org
		peer.name = endorser.Address
		group = append(group, peer)
		endorsersByGroups[endorser.Org] = group
	}

	var sp sortedPeers
	for ind := range endorsersByGroups {
		sp = endorsersByGroups[ind]
		sort.Sort(sp)
		endorsersByGroups[ind] = sp
	}

	fmt.Println("after sorting")
	for org, group := range endorsersByGroups {
		fmt.Printf("mspid: %s\n", org)
		for ind, peer := range group {
			//fmt.Printf("  %d. URL  - %s\n", ind, peer.URL())
			fmt.Printf("  %d. Name - %s\n", ind, peer.Name())
		}
	}

	/**************** end test ****************/

	for _, group := range endorsersByGroups {
		rndmInd, err := rand.Int(bytes.NewBuffer(rndmInit), big.NewInt(int64(len(group))))
		if err != nil {
			return peers, err
		}
		index := int(rndmInd.Int64())
		if index >= len(group) {
			index = len(group) - 1
		}
		peers = append(peers, group[index])
	}

	fmt.Println("selected peers:")
	for ind, peer := range peers {
		if peerCfg, found := ctx.EndpointConfig().PeerConfig(peer.Name()); found {
			peer.url = peerCfg.URL
		}
		fmt.Printf("   %d. MSPID: %s   Name: %s   URL: %s\n", ind, peer.mspID, peer.name, peer.url)
	}

	//hash(hash(Block)||Seq||Pkey)

	return peers, nil
}

// WithCacheTimeout sets the expiration timeout of the cache
func WithCacheTimeout(timeout time.Duration) Opt {
	return func(s *SelectionService) {
		s.cacheTimeout = timeout
	}
}

// SelectionService chooses endorsing peers for a given set of chaincodes using their chaincode policy
type SelectionService struct {
	ctx         context.Client
	channelID   string
	pgResolvers *lazycache.Cache
	//pgLBP            pgresolver.LoadBalancePolicy
	ccPolicyProvider CCPolicyProvider
	discoveryService fab.DiscoveryService
	algorithm        Algorithm
	cacheTimeout     time.Duration
}

type policyProviderFactory func() (CCPolicyProvider, error)

func NewService(context context.Client, channelID string, discovery fab.DiscoveryService, opts ...Opt) (*SelectionService, error) {
	return newService(context, channelID, discovery,
		func() (CCPolicyProvider, error) {
			return newCCPolicyProvider(context, discovery, channelID)
		}, opts...)
}

func newService(ctx context.Client, channelID string, discovery fab.DiscoveryService, factory policyProviderFactory, opts ...Opt) (*SelectionService, error) {
	ccPolicyProvider, err := factory()
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to create cc policy provider")
	}

	service := &SelectionService{
		ctx:              ctx,
		channelID:        channelID,
		discoveryService: discovery,
		ccPolicyProvider: ccPolicyProvider,
		cacheTimeout:     defaultCacheTimeout,
		algorithm:        &algorithmImpl{},
		//pgLBP:            pgresolver.NewRandomLBP(),
	}

	for _, opt := range opts {
		opt(service)
	}

	if service.cacheTimeout == 0 {
		service.cacheTimeout = ctx.EndpointConfig().Timeout(fab.SelectionServiceRefresh)
	}

	//if service.pgLBP == nil {
	//	service.pgLBP = pgresolver.NewRandomLBP()
	//}

	service.pgResolvers = lazycache.New(
		"PG_Resolver_Cache",
		func(key lazycache.Key) (interface{}, error) {
			return service.createPGResolver(key.(*resolverKey))
		},
		lazyref.WithAbsoluteExpiration(service.cacheTimeout),
	)

	return service, nil
}

func getChannelContext(ctx context.Client, channelID string) context.ChannelProvider {
	//Get Channel Context
	return func() (context.Channel, error) {
		//Get Client Context
		clientProvider := func() (context.Client, error) {
			return ctx, nil
		}
		return contextImpl.NewChannel(clientProvider, channelID)
	}
}

// GetEndorsersForChaincode returns the endorsing peers for the given chaincodes
func (s *SelectionService) GetEndorsersForChaincode(chaincodes []*fab.ChaincodeCall, opts ...copts.Opt) ([]fab.Peer, error) {
	if len(chaincodes) == 0 {
		return nil, errors.New("no chaincode IDs provided")
	}

	//params := options.NewParams(opts)

	var chaincodeIDs []string
	for _, cc := range chaincodes {
		chaincodeIDs = append(chaincodeIDs, cc.ID)
	}

	resolver, err := s.getPeerGroupResolver(chaincodeIDs)
	if err != nil {
		return nil, errors.WithMessagef(err, "Error getting peer group resolver for chaincodes [%v] on channel [%s]", chaincodeIDs, s.channelID)
	}

	/********** begin test **********/

	/*
		var endorsingPeers []fab.Peer
		config := s.ctx.EndpointConfig()
		channelPeers := config.ChannelPeers(s.channelID)
		for _, peer := range peers {
			for _, channelPeer := range channelPeers {
				if peer.URL() == channelPeer.URL {
					if channelPeer.EndorsingPeer == true {
						endorsingPeer := peer
						endorsingPeers = append(endorsingPeers, endorsingPeer)
						break
					}
				}
			}
		}

		fmt.Println("Endorsing peers:")
		for ind, peer := range endorsingPeers {
			fmt.Printf("  ind: %d   URL: %s\n", ind, peer.URL())
		}
	*/

	//peersGroups := s.groupPeersByOrgs()
	endorsers, err := s.algorithm.selectEndorsers(s.ctx, s.channelID)
	if err != nil {
		return nil, err
	}

	var peers []fab.Peer
	for _, endorser := range endorsers {
		peer := fab.Peer(endorser)
		peers = append(peers, peer)
	}

	/*********** end test ***********/

	peerGroup, err := resolver.Resolve(peers)
	if err != nil {
		return nil, err
	}
	return peerGroup.Peers(), nil
}

func (s *SelectionService) groupPeersByOrgs() []PeersGroup {

	//var found bool
	var peersGroups []PeersGroup

	//if str, ok := peerCfg.GRPCOptions["ssl-target-name-override"].(string); ok {
	//	serverHostOverride = str
	//}

	peers, err := s.discoveryService.GetPeers()
	if err != nil {
		return nil
	}

	fmt.Println("Channel peers:")
	for ind, peer := range peers {
		fmt.Printf("  ind: %d   URL: %s\n", ind, peer.URL())
	}

	/*

		for _, peer := range peers {
			found = false
			for ind, group := range peersGroups {
				if group.mspID == peer.MSPID() {
					peersGroups[ind].peers = append(peersGroups[ind].peers, peer)
					found = true
					break
				}
			}
			if found == false {
				gr := PeersGroup{}
				gr.mspID = peer.MSPID()
				gr.peers = append(gr.peers, peer)
				peersGroups = append(peersGroups, gr)
			}
		}

		for indGroup, group := range peersGroups {
			if len(group.peers) > 0 {
				//sort.Slice()
				fmt.Printf("%d. MSPID: %s count of peers: %d\n", indGroup, group.mspID, len(group.peers))
				for indPeer, peer := range group.peers {
					fmt.Printf("  %d. %s\n", indPeer, peer.URL())
				}
			}
		}

	*/

	return peersGroups
}

func (s *SelectionService) getPeerGroups(chaincodes []*fab.ChaincodeCall) (map[string][]fab.Peer, error) {

	policy, _ := s.ccPolicyProvider.GetChaincodePolicy(chaincodes[0].ID)
	fmt.Printf("policy rule: %s\n", policy.Rule.String())
	peerGroups := make(map[string][]fab.Peer)
	return peerGroups, nil
}

// Close closes all resources associated with the service
func (s *SelectionService) Close() {
	s.pgResolvers.Close()
}

func (s *SelectionService) getPeerGroupResolver(chaincodeIDs []string) (pgresolver.PeerGroupResolver, error) {
	resolver, err := s.pgResolvers.Get(newResolverKey(s.channelID, chaincodeIDs...))
	if err != nil {
		return nil, err
	}
	return resolver.(pgresolver.PeerGroupResolver), nil
}

func (s *SelectionService) createPGResolver(key *resolverKey) (pgresolver.PeerGroupResolver, error) {

	var policyGroups []pgresolver.GroupRetriever
	for _, ccID := range key.chaincodeIDs {
		policyGroup, err := s.getPolicyGroupForCC(key.channelID, ccID)
		if err != nil {
			return nil, errors.WithMessagef(err, "error retrieving signature policy for chaincode [%s] on channel [%s]", ccID, key.channelID)
		}
		policyGroups = append(policyGroups, policyGroup)
	}

	// Perform an 'and' operation on all of the peer groups
	aggregatePolicyGroupRetriever := func(peerRetriever pgresolver.MSPPeerRetriever) (pgresolver.GroupOfGroups, error) {
		var groups []pgresolver.Group
		for _, f := range policyGroups {
			grps, err := f(peerRetriever)
			if err != nil {
				return nil, err
			}
			groups = append(groups, grps)
		}
		return pgresolver.NewGroupOfGroups(groups).Nof(int32(len(policyGroups)))
	}

	// Create the resolver
	resolver, err := pgresolver.NewPeerGroupResolver(aggregatePolicyGroupRetriever, nil)
	//resolver, err := pgresolver.NewPeerGroupResolver(aggregatePolicyGroupRetriever, s.pgLBP)
	if err != nil {
		return nil, errors.WithMessagef(err, "error creating peer group resolver for chaincodes [%v] on channel [%s]", key.chaincodeIDs, key.channelID)
	}
	return resolver, nil
}

func (s *SelectionService) getPolicyGroupForCC(channelID string, ccID string) (pgresolver.GroupRetriever, error) {
	sigPolicyEnv, err := s.ccPolicyProvider.GetChaincodePolicy(ccID)
	if err != nil {
		return nil, errors.WithMessagef(err, "error querying chaincode [%s] on channel [%s]", ccID, channelID)
	}
	return pgresolver.CompileSignaturePolicy(sigPolicyEnv)
}
