package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/internal/agent/modules"
	"github.com/monirujjaman-dev/server-manager/internal/command"
	"github.com/monirujjaman-dev/server-manager/internal/pki"
)

const commandTimeout = 2 * time.Minute

// updateVerifier applies the command key from a Welcome. The first key seen is stored
// (trust on first use over the authenticated mTLS stream, for agents enrolled before the
// key existed); a different key later is refused so a compromised TLS endpoint alone
// cannot start issuing commands.
func (a *Agent) updateVerifier(serverID uuid.UUID, offered []byte) {
	stored, err := pki.ReadCommandPublicKey(a.cfg.CommandKeyFile)
	switch {
	case err == nil:
		if len(offered) > 0 && !bytes.Equal(stored, offered) {
			a.log.Error("control plane offered a different command key than the one stored; commands will be rejected",
				"file", a.cfg.CommandKeyFile)
		}
	case errors.Is(err, os.ErrNotExist) && len(offered) == ed25519.PublicKeySize:
		if err := pki.WriteCommandPublicKey(a.cfg.CommandKeyFile, offered); err != nil {
			a.log.Error("store command key", "err", err)
			return
		}
		a.log.Info("stored command verification key", "file", a.cfg.CommandKeyFile)
		stored = offered
	default:
		a.log.Warn("no command verification key; commands will be rejected", "err", err)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.verifier == nil || !bytes.Equal(a.verifierKey, stored) || a.verifierID != serverID {
		a.verifier = command.NewVerifier(stored, serverID)
		a.verifierKey, a.verifierID = stored, serverID
	}
}

func (a *Agent) getVerifier() *command.Verifier {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.verifier
}

// handleCommand runs one command with bounded concurrency. It uses the agent's run
// context, so a command keeps running across reconnects and its result is sent on
// whichever stream is open next.
func (a *Agent) handleCommand(ctx context.Context, cmd *agentv1.Command) {
	select {
	case a.sem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	defer func() { <-a.sem }()
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	res := a.execute(ctx, cmd)
	select {
	case a.results <- res:
	case <-ctx.Done():
	}
}

func (a *Agent) execute(ctx context.Context, cmd *agentv1.Command) *agentv1.CommandResult {
	id := unverifiedID(cmd)
	reject := func(err error) *agentv1.CommandResult {
		a.log.Warn("command rejected", "job_id", id, "err", err)
		return &agentv1.CommandResult{Id: id, Status: agentv1.CommandStatus_COMMAND_STATUS_REJECTED, Error: err.Error()}
	}
	v := a.getVerifier()
	if v == nil {
		return reject(errors.New("no command verification key"))
	}
	env, err := v.Verify(cmd)
	if err != nil {
		return reject(err)
	}
	info, _ := command.Describe(env.GetRequest())
	log := a.log.With("job_id", env.GetId(), "action", info.Name)

	if info.Privileged {
		res, err := a.privd.Execute(ctx, cmd)
		if err != nil {
			log.Error("privileged helper call failed", "err", err)
			return &agentv1.CommandResult{Id: env.GetId(), Status: agentv1.CommandStatus_COMMAND_STATUS_FAILED,
				Error: "privileged helper unavailable: " + err.Error()}
		}
		res.Id = env.GetId()
		log.Info("command finished", "status", res.GetStatus().String())
		return res
	}

	result, err := a.runLocal(ctx, env.GetRequest())
	if err != nil {
		log.Info("command failed", "err", err)
		return &agentv1.CommandResult{Id: env.GetId(), Status: agentv1.CommandStatus_COMMAND_STATUS_FAILED, Error: err.Error()}
	}
	log.Info("command finished", "status", "succeeded")
	return &agentv1.CommandResult{Id: env.GetId(), Status: agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED, Result: result}
}

// runLocal executes read-only actions inside the unprivileged agent.
func (a *Agent) runLocal(ctx context.Context, req *agentv1.ActionRequest) (*agentv1.ActionResult, error) {
	switch r := req.GetAction().(type) {
	case *agentv1.ActionRequest_SystemInfo:
		info, err := a.host.SystemInfo()
		if err != nil {
			return nil, err
		}
		return &agentv1.ActionResult{Result: &agentv1.ActionResult_SystemInfo{SystemInfo: info}}, nil
	case *agentv1.ActionRequest_ServiceList:
		list, err := modules.ListServices(ctx, a.systemd, r.ServiceList)
		if err != nil {
			return nil, err
		}
		return &agentv1.ActionResult{Result: &agentv1.ActionResult_ServiceList{ServiceList: list}}, nil
	case *agentv1.ActionRequest_ProcessList:
		list, err := a.host.ListProcesses(ctx, r.ProcessList)
		if err != nil {
			return nil, err
		}
		return &agentv1.ActionResult{Result: &agentv1.ActionResult_ProcessList{ProcessList: list}}, nil
	case *agentv1.ActionRequest_LogQuery:
		res, err := a.journal.Query(ctx, r.LogQuery)
		if err != nil {
			return nil, err
		}
		return &agentv1.ActionResult{Result: &agentv1.ActionResult_LogQuery{LogQuery: res}}, nil
	case *agentv1.ActionRequest_AuthLog:
		res, err := a.journal.AuthLog(ctx, r.AuthLog)
		if err != nil {
			return nil, err
		}
		return &agentv1.ActionResult{Result: &agentv1.ActionResult_AuthLog{AuthLog: res}}, nil
	default:
		return nil, fmt.Errorf("unsupported action %T", r)
	}
}

func unverifiedID(cmd *agentv1.Command) string {
	env := &agentv1.CommandEnvelope{}
	if proto.Unmarshal(cmd.GetEnvelope(), env) != nil {
		return ""
	}
	return env.GetId()
}
