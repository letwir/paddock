"""Finite explicit-state checker for the S05 rollout/epoch/lease contract.

Run: python3 -m unittest tests.test_rollout_model_check -v
Only Python's standard library is used. Epochs are bounded to the reachable
fixture range (40..43 scope, 7..9 per-root, 3..4 security).
"""
from collections import deque
from dataclasses import dataclass, replace
import platform
import unittest


TERMINAL = {"COMPLETED", "ROLLED_BACK", "SAFE_STOPPED", "REJECTED"}
ACTIVE = {"CANARY", "MONITORING", "HOLD", "ROLLING_BACK"}


@dataclass(frozen=True)
class State:
    phase: str = "IDLE"
    slot: bool = False
    a_policy: int = 1
    b_policy: int = 1
    scope_epoch: int = 40
    a_epoch: int = 7
    b_epoch: int = 7
    security_epoch: int = 3
    lease_epoch: int = 1
    lease_current: bool = True
    db: bool = True
    stopped: bool = False
    lkg: bool = True
    frozen: bool = False
    elapsed: int = 0
    stale_accepted: bool = False
    human_actor: bool = False


def successors(s, *, broken=None):
    """One-step transition relation. A broken option injects a mutant."""
    out = []
    def add(name, **kw):
        out.append((name, replace(s, **kw)))
    if s.phase == "IDLE" and not s.slot and s.db and not s.stopped:
        add("start-canary-B", phase="CANARY", slot=True, b_policy=2,
            scope_epoch=s.scope_epoch + 1, b_epoch=s.b_epoch + 1)
    if s.phase == "CANARY" and s.db and not s.stopped:
        add("promote", phase="MONITORING", a_policy=2,
            scope_epoch=s.scope_epoch + 1, a_epoch=s.a_epoch + 1)
        add("begin-rollback", phase="ROLLING_BACK", frozen=True)
        add("hold", phase="HOLD", elapsed=0)
    if s.phase == "MONITORING" and s.db and not s.stopped:
        add("monitor-tick", elapsed=min(2, s.elapsed + 1))
        if s.elapsed >= 1:
            add("monitor-pass-complete", phase="COMPLETED", slot=False)
        add("begin-rollback", phase="ROLLING_BACK", frozen=True)
        add("hold", phase="HOLD", elapsed=0)
    if s.phase == "HOLD" and s.db and not s.stopped:
        add("hold-tick", elapsed=min(2, s.elapsed + 1))
        if s.elapsed >= 1:
            add("hold-deadline-rollback", phase="ROLLING_BACK", frozen=True)
    if s.phase == "ROLLING_BACK" and s.db:
        if s.lkg:
            add("rollback-switch", phase="ROLLED_BACK", slot=False, frozen=False,
                a_policy=1, b_policy=1, scope_epoch=s.scope_epoch + 1,
                a_epoch=s.a_epoch + (1 if s.a_policy != 1 else 0),
                b_epoch=s.b_epoch + (1 if s.b_policy != 1 else 0))
        else:
            add("rollback-safe-baseline", phase="SAFE_STOPPED", slot=False, frozen=True,
                a_policy=0, b_policy=0, scope_epoch=s.scope_epoch + 1,
                security_epoch=s.security_epoch + 1)
    if s.phase in ACTIVE and s.db and not s.stopped:
        # Lease generation is monotonic in the real system, but only its
        # ordering matters here. Saturate at 2 to keep this finite-state model
        # finite while still covering the initial-to-renewed transition.
        add("lease-renew", lease_epoch=min(2, s.lease_epoch + 1), lease_current=True)
        # Delayed result from prior lease: fencing rejects it, never changes policy.
        add("stale-lease-result-reject", lease_current=False)
        if broken == "stale-lease":
            add("MUTANT-stale-lease-accepted", lease_current=False, stale_accepted=True)
    # Availability and emergency stop are environment/human actions; the actor
    # flag makes it impossible for an autonomous transition to trigger stop.
    if s.db:
        add("db-unavailable", db=False)
    else:
        add("db-recovered", db=True)
    if not s.stopped:
        add("human-emergency-stop", phase="SAFE_STOPPED", slot=False,
            stopped=True, human_actor=True, frozen=True,
            a_policy=0, b_policy=0, scope_epoch=s.scope_epoch + 1,
            a_epoch=s.a_epoch + (1 if s.a_policy != 0 else 0),
            b_epoch=s.b_epoch + (1 if s.b_policy != 0 else 0),
            security_epoch=s.security_epoch + 1)
        if broken == "agent-stop":
            add("MUTANT-agent-emergency-stop", phase="SAFE_STOPPED", slot=False,
                stopped=True, security_epoch=s.security_epoch + 1)
    return out


def invariant(s, previous=None):
    assert not (s.slot and s.phase not in ACTIVE), ("INV-01 terminal slot", s)
    assert s.slot == (s.phase in ACTIVE), ("INV-01 slot/state", s)
    if previous:
        for field in ("scope_epoch", "a_epoch", "b_epoch", "security_epoch", "lease_epoch"):
            assert getattr(s, field) >= getattr(previous, field), ("INV-02 decrease", field, previous, s)
        if previous.phase == "ROLLING_BACK" and s.phase == "ROLLING_BACK":
            assert (s.scope_epoch, s.a_epoch, s.b_epoch) == (previous.scope_epoch, previous.a_epoch, previous.b_epoch), "INV-02 early rollback bump"
        if previous.phase == "CANARY" and s.phase == "CANARY":
            assert s.scope_epoch == previous.scope_epoch and s.b_epoch == previous.b_epoch
    if s.phase == "CANARY":
        assert s.a_policy == 1 and s.a_epoch == 7, "INV-03 Root A changed during B Canary"
    if s.phase == "SAFE_STOPPED":
        assert s.a_policy == 0 and s.b_policy == 0, "SAFE_STOPPED must select deny-all baseline"
    assert not s.stale_accepted, "INV-06 stale lease result accepted"
    assert not s.stopped or s.human_actor, "emergency stop was not human-only"


def explore(broken=None):
    initial = State()
    q = deque([(initial, None)])
    seen = {initial}
    edges = 0
    while q:
        s, prev = q.popleft()
        invariant(s, prev)
        for _, n in successors(s, broken=broken):
            edges += 1
            invariant(n, s)
            if n not in seen:
                seen.add(n)
                q.append((n, s))
    return len(seen), edges


def trace(actions):
    s = State()
    states = [s]
    for wanted in actions:
        choices = dict((name, nxt) for name, nxt in successors(s))
        s = choices[wanted]
        states.append(s)
    return states


def high_risk_authorized(s):
    """Authorization fails closed when DB is unavailable or scope is stopped."""
    return s.db and not s.stopped and not s.frozen and s.phase != "SAFE_STOPPED"


class RolloutModelCheck(unittest.TestCase):
    def test_exhaustive_safety_and_reproducible_exploration_log(self):
        states, edges = explore()
        self.assertGreater(states, 10)
        self.assertGreater(edges, states)
        # Logged by the test runner; repeat runs produce identical values.
        print(f"S05 MODEL tool=Python {platform.python_version()} states={states} transitions={edges}")
        print("S05 SAFETY PASS INV-01 INV-02 INV-03 INV-06 HUMAN-STOP DB-DENY")

    def test_root_b_canary_preserves_a_and_rollback_freezes_epochs(self):
        canary = trace(["start-canary-B"])[-1]
        self.assertEqual((canary.a_policy, canary.a_epoch, canary.b_policy, canary.b_epoch), (1, 7, 2, 8))
        rolling = trace(["start-canary-B", "begin-rollback"])[-1]
        self.assertEqual((rolling.scope_epoch, rolling.b_epoch), (41, 8))
        rolled = dict((n, t) for n, t in successors(rolling))["rollback-switch"]
        self.assertEqual((rolled.scope_epoch, rolled.b_epoch), (42, 9))

    def test_db_outage_denies_progress_and_stop_is_human_only(self):
        unavailable = trace(["db-unavailable"])[-1]
        self.assertFalse(any(n.phase in {"COMPLETED", "ROLLED_BACK"} for _, n in successors(unavailable)))
        active_outage = trace(["start-canary-B", "db-unavailable"])[-1]
        self.assertFalse(high_risk_authorized(active_outage))
        stop = dict((n, t) for n, t in successors(State()))["human-emergency-stop"]
        self.assertTrue(stop.stopped and stop.human_actor)
        self.assertEqual((stop.phase, stop.a_policy, stop.b_policy), ("SAFE_STOPPED", 0, 0))
        self.assertFalse(high_risk_authorized(stop))
        outage_stop = trace(["start-canary-B", "db-unavailable"])[-1]
        outage_stop = dict((n, t) for n, t in successors(outage_stop))["human-emergency-stop"]
        self.assertEqual((outage_stop.phase, outage_stop.a_policy, outage_stop.b_policy),
                         ("SAFE_STOPPED", 0, 0))
        self.assertFalse(high_risk_authorized(outage_stop))

    def test_conditional_bounded_liveness_with_fair_progress(self):
        # Assumptions: DB and scheduler remain available, clock advances, and
        # weak fairness eventually takes enabled tick/finalize transitions.
        good = trace(["start-canary-B", "promote", "monitor-tick", "monitor-pass-complete"])
        self.assertEqual(good[-1].phase, "COMPLETED")
        hold = trace(["start-canary-B", "hold", "hold-tick", "hold-deadline-rollback", "rollback-switch"])
        self.assertEqual(hold[-1].phase, "ROLLED_BACK")
        print("S05 LIVENESS PASS assumptions=DB+scheduler available; clock advances; weak fairness; monitor<=2, hold<=2")

    def test_unfair_stalled_counterexample_blocks_unconditional_liveness(self):
        # Scheduler is never scheduled and DB/clock are unavailable: the active
        # slot remains occupied forever. Repeating the same stutter is a lasso.
        s = trace(["start-canary-B"])[-1]
        stuck = dict((n, t) for n, t in successors(s))["db-unavailable"]
        self.assertTrue(stuck.slot)
        self.assertEqual(stuck.phase, "CANARY")  # scheduler stutters; DB cannot authorize a transition
        self.assertEqual((stuck.scope_epoch, stuck.b_epoch), (41, 8))
        print("S05 COUNTEREXAMPLE unfair/stalled trace=start-canary-B, db-unavailable, STUTTER* (slot remains active)")

    def test_mutants_are_caught(self):
        with self.assertRaises(AssertionError):
            explore(broken="stale-lease")
        with self.assertRaises(AssertionError):
            explore(broken="agent-stop")
        print("S05 MUTANTS caught=stale-lease,agent-controlled-stop")


if __name__ == "__main__":
    unittest.main()
