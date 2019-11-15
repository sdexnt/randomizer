/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package channelconfig

import (
	"fmt"

	cb "github.com/hyperledger/fabric-sdk-go/third_party/github.com/hyperledger/fabric/protos/common"
	pb "github.com/hyperledger/fabric-sdk-go/third_party/github.com/hyperledger/fabric/protos/peer"
	"github.com/pkg/errors"
)

const (
	// AnchorPeersKey is the key name for the AnchorPeers ConfigValue
	AnchorPeersKey = "AnchorPeers"
	// EndorsersKey is the key name for the Endorsers ConfigValue
	EndorsersKey = "Endorsers"
)

// ApplicationOrgProtos are deserialized from the config
type ApplicationOrgProtos struct {
	AnchorPeers *pb.AnchorPeers
	Endorsers   *pb.Endorsers
}

// ApplicationOrgConfig defines the configuration for an application org
type ApplicationOrgConfig struct {
	*OrganizationConfig
	protos *ApplicationOrgProtos
	name   string
}

// NewApplicationOrgConfig creates a new config for an application org
func NewApplicationOrgConfig(id string, orgGroup *cb.ConfigGroup, mspConfig *MSPConfigHandler) (*ApplicationOrgConfig, error) {
	if len(orgGroup.Groups) > 0 {
		return nil, fmt.Errorf("ApplicationOrg config does not allow sub-groups")
	}

	protos := &ApplicationOrgProtos{}
	orgProtos := &OrganizationProtos{}

	logger.Infof("begin DeserializeProtoValuesFromGroup")

	if err := DeserializeProtoValuesFromGroup(orgGroup, protos, orgProtos); err != nil {
		return nil, errors.Wrap(err, "failed to deserialize values")
	}

	aoc := &ApplicationOrgConfig{
		name:   id,
		protos: protos,
		OrganizationConfig: &OrganizationConfig{
			name:             id,
			protos:           orgProtos,
			mspConfigHandler: mspConfig,
		},
	}

	if err := aoc.Validate(); err != nil {
		return nil, err
	}

	return aoc, nil
}

// AnchorPeers returns the list of anchor peers of this Organization
func (aog *ApplicationOrgConfig) AnchorPeers() []*pb.AnchorPeer {
	return aog.protos.AnchorPeers.AnchorPeers
}

// Endorsers returns the list of endorsers of this Organization
func (aog *ApplicationOrgConfig) Endorsers() []*pb.Endorser {
	return aog.protos.Endorsers.Endorsers
}

func (aoc *ApplicationOrgConfig) Validate() error {
	logger.Debugf("Anchor peers for org %s are %v", aoc.name, aoc.protos.AnchorPeers)
	return aoc.OrganizationConfig.Validate()
}
