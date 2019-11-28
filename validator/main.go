package main

import (
	"fmt"
	"plugin"

	validation "github.com/hyperledger/fabric/core/handlers/validation/api"
	"github.com/hyperledger/fabric/protos/common"
)

const (
	namespace      = "namespace"
	txPosition     = 1
	actionPosition = 1
)

func UseValidator() error {
	handler, err := plugin.Open("handlers/validator.so")
	if err != nil {
		return err
	}
	//var factory validation.PluginFactory
	f, err := handler.Lookup("NewPluginFactory")
	if err != nil {
		return err
	}
	factory := f.(func() validation.PluginFactory)()
	var validator validation.Plugin
	validator = factory.New()
	if validator == nil {
		return fmt.Errorf("validator is nil")
	}
	err = validator.Init()
	if err != nil {
		return err
	}

	block := &common.Block{}
	block.Header = &common.BlockHeader{}
	block.Header.Number = 5
	err = validator.Validate(block, "namespace", txPosition, actionPosition)
	return err
}

func main() {

	err := UseValidator()
	if err != nil {
		fmt.Println(err)
	}
}
