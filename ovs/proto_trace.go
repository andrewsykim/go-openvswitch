// Copyright 2017 DigitalOcean.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ovs

import (
	"encoding"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	// ErrInvalidProtoTrace is returned when the output from
	// ovs-appctl ofproto/trace is in an unexpected format
	ErrInvalidProtoTrace  = errors.New("invalid ofproto/trace output")
	datapathActionsRegexp = regexp.MustCompile(`Datapath actions: (.*)`)
	initialFlowRegexp     = regexp.MustCompile(`Flow: (.*)`)
	finalFlowRegexp       = regexp.MustCompile(`Final flow: (.*)`)
)

const (
	popvlan  = "popvlan"
	pushvlan = "pushvlan"
	drop     = "drop"
)

type DataPathAction interface {
	encoding.TextUnmarshaler
}

func NewDataPathAction(action string) DataPathAction {
	return &dataPathAction{
		action: action,
	}
}

type dataPathAction struct {
	action string
}

func (d *dataPathAction) UnmarshalText(b []byte) error {
	action := string(b)
	if _, err := strconv.Atoi(action); err == nil {
		// data path action is to an output port
		d.action = action
		return nil
	}

	if strings.HasPrefix(action, pushvlan) {
		d.action = pushvlan
		return nil
	}

	switch action {
	case popvlan:
		d.action = popvlan
	case drop:
		d.action = drop
	default:
		return fmt.Errorf("unknown data path actions: %v", action)
	}

	return nil
}

type DataPathFlows struct {
	Protocol Protocol
	Matches  []Match
}

func (df *DataPathFlows) UnmarshalText(b []byte) error {
	matches := strings.Split(string(b), ",")

	if len(matches) == 0 {
		return errors.New("error unmarshalling text, no comma delimiter found")
	}

	// first string is always the protocol
	df.Protocol = Protocol(matches[0])

	matches = matches[1:]

	for _, match := range matches {
		kv := strings.Split(match, "=")
		if len(kv) != 2 {
			return fmt.Errorf("unexpected match format for match %q", match)
		}

		m, err := parseMatch(kv[0], kv[1])
		if err != nil {
			return err
		}

		df.Matches = append(df.Matches, m)
	}

	return nil
}

// ProtoTrace is a type representing output from ovs-app-ctl ofproto/trace
type ProtoTrace struct {
	InputFlow       *DataPathFlows
	FinalFlow       *DataPathFlows
	DataPathActions []DataPathAction
}

// UnmarshalText unmarshals ProtoTrace text into a ProtoTrace type.
// Not implemented yet.
func (pt *ProtoTrace) UnmarshalText(b []byte) error {
	lines := strings.Split(string(b), "\n")
	for _, line := range lines {
		if matches, matched := checkForDataPathActions(line); matched {
			// first index is always the left most match, following
			// are the actual matches
			actions := splitDatapathActions(matches[1])
			for _, action := range actions {
				d := &dataPathAction{}
				err := d.UnmarshalText([]byte(action))
				if err != nil {
					return err
				}
				pt.DataPathActions = append(pt.DataPathActions, d)
			}
			continue
		}

		if matches, matched := checkForInputFlow(line); matched {
			flow := &DataPathFlows{}
			err := flow.UnmarshalText([]byte(matches[1]))
			if err != nil {
				return err
			}

			pt.InputFlow = flow
			continue
		}

		if matches, matched := checkForFinalFlow(line); matched {
			flow := &DataPathFlows{}
			err := flow.UnmarshalText([]byte(matches[1]))
			if err != nil {
				return err
			}

			pt.FinalFlow = flow
			continue
		}
	}

	return nil
}

func splitDatapathActions(actions string) []string {
	parens := []byte{}
	action_bytes := make([]byte, len(actions))

	for i := 0; i < len(actions); i += 1 {
		action_bytes[i] = actions[i]
		switch {
			case actions[i] == ',':
				if len(parens) == 0 {
					action_bytes[i] = '\t';
				}
			case actions[i] == '(':
				parens = append(parens, ')')
			case len(parens) != 0 && actions[i] == parens[len(parens)-1]:
				parens = parens[:len(parens)-1]
		}
	}
	return strings.Split(string(action_bytes), "\t")
}

func checkForDataPathActions(s string) ([]string, bool) {
	matches := datapathActionsRegexp.FindStringSubmatch(s)
	if matches == nil || len(matches) == 0 {
		return matches, false
	}

	return matches, true
}

func checkForInputFlow(s string) ([]string, bool) {
	matches := initialFlowRegexp.FindStringSubmatch(s)
	if matches == nil || len(matches) == 0 {
		return matches, false
	}

	return matches, true
}

func checkForFinalFlow(s string) ([]string, bool) {
	matches := finalFlowRegexp.FindStringSubmatch(s)
	if matches == nil || len(matches) == 0 {
		return matches, false
	}

	return matches, true
}
