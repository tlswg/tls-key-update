///////////////////////////////////////////////////////////////
// Extended Key Update (DTLS 1.3) - Crossed Requests Model
//
// Goal: verify crossed-requests handling per Appendix B.2.1/B.2.2/B.2.3
// of draft-ietf-tls-extended-key-update:
//   - Both peers MAY initiate; Req messages can cross due to loss/reordering.
//   - Crossed-requests rule (compare KeyShareEntry.key_exchange):
//       * peer < local  => ignore peer Req
//       * peer == local => abort with "unexpected_message"
//       * peer > local  => abandon local update; act as responder
//   - DTLS update flow:
//       Initiator: Req -> Resp -> NKU -> ACK (rx bumped on Resp; tx bumped on ACK)
//       Responder: on NKU: bump rx+tx and send ACK
//
// This model keeps cryptography abstract (epochs only) and includes:
//   - APP traffic allowed any time
//   - simple loss/reordering via two paths each direction
//   - bounded retransmissions for Req and NKU
//   - optional abstract post-handshake authentication (PHA) flow:
//       PHAReq -> PHAFin
//     with EKU deferral while PHA is pending (no epoch progress during PHA)
//   - optional abstract Exported Authenticator (RFC 9261):
//       EAReq -> EAFin (application-triggered, both directions)
//
// Liveness update (2026-02):
//   Under lossy stress, retries can be exhausted without protocol progress.
//   We model this explicitly with local abort states (abort_a/abort_b) so that
//   liveness can distinguish:
//     - successful completion (done_*), and
//     - bounded-failure termination after retry exhaustion (abort_*).
//
// Network progress update (2026-02):
//   To avoid transport-level head-of-line artifacts in liveness checks:
//     - if the destination peer has aborted, packets to that peer are dropped;
//     - delivery into to_a/to_b is attempted only when the destination queue
//       is not full (nfull(...)); otherwise another transition can be explored.
///////////////////////////////////////////////////////////////

/* --- Configuration --- */
#ifndef INIT_RX_A
#define INIT_RX_A 0
#endif
#ifndef INIT_TX_A
#define INIT_TX_A 0
#endif
#ifndef INIT_RX_B
#define INIT_RX_B 0
#endif
#ifndef INIT_TX_B
#define INIT_TX_B 0
#endif

/* Both peers initiate to exercise crossed-requests logic */
#ifndef INITIATE_A
#define INITIATE_A 1
#endif
#ifndef INITIATE_B
#define INITIATE_B 1
#endif

/* KeyShareEntry.key_exchange values (set equal to force "unexpected_message") */
#ifndef KX_A
#define KX_A 10
#endif
#ifndef KX_B
#define KX_B 20
#endif

/* Reduce state space: set to 0 for no APP traffic */
#ifndef APP_QUOTA
#define APP_QUOTA 0
#endif

/* Loss budget (for liveness checks, set to 0) */
#ifndef DROPS
#define DROPS 2
#endif

/* Bounded retransmissions (increase for lossy runs) */
#ifndef REQ_RETRIES
#define REQ_RETRIES 4
#endif
#ifndef NKU_RETRIES
#define NKU_RETRIES 4
#endif
/* Bounded wait while acting as responder (waiting for peer NKU). */
#ifndef RESP_WAIT_RETRIES
#define RESP_WAIT_RETRIES 4
#endif
#ifndef ENABLE_PHA
#define ENABLE_PHA 0
#endif
#ifndef PHA_TRIGGER_B
#define PHA_TRIGGER_B 1
#endif
#ifndef ENABLE_EA
#define ENABLE_EA 0
#endif
#ifndef EA_TRIGGER_A
#define EA_TRIGGER_A 1
#endif
#ifndef EA_TRIGGER_B
#define EA_TRIGGER_B 1
#endif
#ifndef EA_SPONT_TRIGGER_B
#define EA_SPONT_TRIGGER_B 1
#endif

/* Network loss budget */
byte drops_left = DROPS;

mtype = { Req, Resp, NKU, ACK, APP, PHAReq, PHAFin, EAReq, EAFin };

/* Visible delivery channels (post-network) */
chan to_a = [4] of { mtype, byte, byte, bool }; /* (type, tag_epoch, kx, accepted) */
chan to_b = [4] of { mtype, byte, byte, bool };

/* Hidden network paths (reordering) */
chan a2b_p1 = [2] of { mtype, byte, byte, bool };
chan a2b_p2 = [2] of { mtype, byte, byte, bool };
chan b2a_p1 = [2] of { mtype, byte, byte, bool };
chan b2a_p2 = [2] of { mtype, byte, byte, bool };

#define A2B_SEND(t,e,k,a)  if :: a2b_p1!t,e,k,a :: a2b_p2!t,e,k,a fi
#define B2A_SEND(t,e,k,a)  if :: b2a_p1!t,e,k,a :: b2a_p2!t,e,k,a fi
#define A_RECV(t,e,k,a)    to_a ? t,e,k,a
#define B_RECV(t,e,k,a)    to_b ? t,e,k,a

/* --- Global markers (properties) --- */
bool done_a = false;
bool done_b = false;
bool unexpected = false;
bool abort_a = false;
bool abort_b = false;
bool pha_pending = false;
bool pha_done = false;
bool pha_req_sent = false;
bool ea_pending = false;
bool ea_done = false;
bool ea_req_sent_a = false;
bool ea_req_sent_b = false;
bool ea_spont_pending_b = false;
bool ea_spont_sent_b = false;
bool deferred_req_a = false;
bool deferred_req_b = false;
byte deferred_req_e_a = 255;
byte deferred_req_e_b = 255;
byte deferred_req_kx_a = 255;
byte deferred_req_kx_b = 255;

#define AUTH_PENDING (pha_pending || ea_pending || ea_spont_pending_b)

/* Snapshots for LTL checks once peers are done */
byte final_rx_a = 255;
byte final_tx_a = 255;
byte final_rx_b = 255;
byte final_tx_b = 255;

/* --- Network process: Loss + Reordering + non-blocking delivery --- */
proctype Network() priority 2 {
    mtype t; byte e; byte k; bool a;
    do
    /* Terminate when both peers reached a terminal state (done or abort)
       and the in-flight network queues are drained. */
    :: ((done_a || abort_a) && (done_b || abort_b) &&
        len(a2b_p1) == 0 && len(a2b_p2) == 0 &&
        len(b2a_p1) == 0 && len(b2a_p2) == 0) -> break

    :: (len(a2b_p1) > 0) ->
        a2b_p1 ? t,e,k,a;
        if
        :: abort_b -> skip
        :: (drops_left > 0) -> drops_left--
        :: nfull(to_b) -> to_b ! t,e,k,a
        fi
    :: (len(a2b_p2) > 0) ->
        a2b_p2 ? t,e,k,a;
        if
        :: abort_b -> skip
        :: (drops_left > 0) -> drops_left--
        :: nfull(to_b) -> to_b ! t,e,k,a
        fi
    :: (len(b2a_p1) > 0) ->
        b2a_p1 ? t,e,k,a;
        if
        :: abort_a -> skip
        :: (drops_left > 0) -> drops_left--
        :: nfull(to_a) -> to_a ! t,e,k,a
        fi
    :: (len(b2a_p2) > 0) ->
        b2a_p2 ? t,e,k,a;
        if
        :: abort_a -> skip
        :: (drops_left > 0) -> drops_left--
        :: nfull(to_a) -> to_a ! t,e,k,a
        fi
    od
}

/* --- Peer logic (parameterized by role/channel) --- */
proctype PeerA() priority 1
{
    /* epochs */
    byte rx = INIT_RX_A;
    byte tx = INIT_TX_A;
    byte old_rx = 255;
    bool retain_old = false;

    bool updating = false;
    bool initiated = false;
    bool derived = false; /* initiator derived EKU secrets (MUST NOT be deferred) */
    bool completed = false;
    byte local_kx = KX_A;
    byte peer_kx_active = 255; /* peer's active Req key_exchange (for retransmits) */
    byte req_retries = REQ_RETRIES;
    byte nku_retries = NKU_RETRIES;
    byte resp_wait_retries = RESP_WAIT_RETRIES;
    byte app_quota = APP_QUOTA;
    byte e; byte kx; bool acc;

    if
    :: (INITIATE_A) ->
        atomic {
            updating = true;
            initiated = true;
            A2B_SEND(Req, tx, local_kx, true);
        }
    :: else -> skip
    fi;

WAIT_RESP:
    do
    :: (!AUTH_PENDING && deferred_req_a) ->
        if
        :: (!updating && (deferred_req_e_a == rx || (retain_old && deferred_req_e_a == old_rx))) ->
            updating = true;
            initiated = false;
            peer_kx_active = deferred_req_kx_a;
            A2B_SEND(Resp, tx, local_kx, true)
        :: else -> skip
        fi;
        deferred_req_a = false

    :: (ENABLE_EA && EA_TRIGGER_A && !ea_req_sent_a && !updating && !AUTH_PENDING) ->
        A2B_SEND(EAReq, tx, 0, true);
        ea_pending = true;
        ea_req_sent_a = true

    /* APP send anytime */
    :: (app_quota > 0) ->
        A2B_SEND(APP, tx, 0, true);
        app_quota--

    /* APP receive anytime */
    :: A_RECV(APP, e, kx, acc) ->
        if
        :: (e == rx) ->
            if
            :: retain_old -> retain_old = false
            :: else -> skip
            fi
        :: (retain_old && e == old_rx) -> skip
        :: else -> skip
        fi

    :: A_RECV(PHAReq, e, kx, acc) ->
        A2B_SEND(PHAFin, tx, 0, true)
    :: A_RECV(EAReq, e, kx, acc) ->
        A2B_SEND(EAFin, tx, 0, true)
    :: A_RECV(EAFin, e, kx, acc) ->
        if
        :: ea_pending ->
            ea_pending = false;
            ea_done = true
        :: else ->
            /* spontaneous server EA is acknowledged in DTLS */
            A2B_SEND(ACK, tx, 0, true);
            ea_done = true
        fi

    /* retransmit Req while waiting (only when no pending inbound message) */
    :: (updating && initiated && req_retries > 0 && len(to_a) == 0) ->
        A2B_SEND(Req, tx, local_kx, true);
        req_retries--
    :: (updating && initiated && req_retries == 0 && len(to_a) == 0) ->
        /* No further progress possible as initiator after bounded Req retries. */
        abort_a = true;
        updating = false;
        goto ABORT_A
    /* waiting as responder for peer NKU: bounded timeout only if no inbound
       messages are pending anywhere on the inbound path (network + mailbox). */
    :: (updating && !initiated &&
        resp_wait_retries > 0 &&
        len(to_a) == 0 && len(b2a_p1) == 0 && len(b2a_p2) == 0) ->
        resp_wait_retries--
    :: (updating && !initiated &&
        resp_wait_retries == 0 &&
        len(to_a) == 0 && len(b2a_p1) == 0 && len(b2a_p2) == 0) ->
        abort_a = true;
        updating = false;
        goto ABORT_A

    /* crossed Req */
    :: A_RECV(Req, e, kx, acc) ->
        if
        :: AUTH_PENDING ->
            deferred_req_a = true;
            deferred_req_e_a = e;
            deferred_req_kx_a = kx;
            A2B_SEND(ACK, tx, 0, true)
        :: ((e == rx) || (retain_old && e == old_rx)) ->
            if
            :: (!updating) ->
                /* act as responder */
                updating = true;
                initiated = false;
                peer_kx_active = kx;
                A2B_SEND(Resp, tx, local_kx, true);
            :: (initiated) ->
                /* crossed-requests rule */
                if
                :: (kx < local_kx) -> skip /* ignore */
                :: (kx == local_kx) -> unexpected = true; break
                :: else ->
                    /* abandon local update; act as responder */
                    initiated = false;
                    peer_kx_active = kx;
                    A2B_SEND(Resp, tx, local_kx, true);
                fi
            :: else ->
                /* responder sees (re)transmitted Req: resend Resp if same key_exchange */
                if
                :: (kx == peer_kx_active) -> A2B_SEND(Resp, tx, local_kx, true)
                :: else -> unexpected = true; break
                fi
            fi
        :: else ->
            /* discard */
            skip
        fi

    /* receive Resp (implicit ACK of Req) */
    :: A_RECV(Resp, e, kx, acc) ->
        if
        :: AUTH_PENDING -> skip
        :: (e != rx) -> skip
        :: (!updating || !initiated) ->
            /* ignore stray Resp */
            skip
        :: else ->
            /* Derive secrets now (initiator MUST NOT defer); activate retention; bump rx */
            derived = true;
            old_rx = rx;
            retain_old = true;
            rx = rx + 1;
            /* send NKU tagged with old tx */
            A2B_SEND(NKU, tx, 0, true);
            goto WAIT_ACK
        fi

    /* responder receives NKU: bump rx+tx and ACK */
    :: A_RECV(NKU, e, kx, acc) ->
        if
        :: AUTH_PENDING -> skip
        :: !((e == rx) || (retain_old && e == old_rx)) -> skip
        :: (updating && !initiated && e == rx) ->
            old_rx = rx;
            retain_old = true;
            rx = rx + 1;
            tx = tx + 1;
            A2B_SEND(ACK, tx, 0, true);
            assert(tx == rx);
            updating = false;
            completed = true;
            final_rx_a = rx;
            final_tx_a = tx;
            done_a = true;
        :: (completed && retain_old && e == old_rx) ->
            /* duplicate NKU (initiator retransmit after lost ACK): retransmit ACK */
            A2B_SEND(ACK, tx, 0, true)
        :: else ->
            /* ignore stray/duplicate NKU */
            skip
        fi

    :: A_RECV(PHAFin, e, kx, acc) -> skip
    :: A_RECV(EAReq, e, kx, acc) -> A2B_SEND(EAFin, tx, 0, true)
    :: A_RECV(EAFin, e, kx, acc) ->
        if
        :: ea_pending ->
            ea_pending = false;
            ea_done = true
        :: else ->
            A2B_SEND(ACK, tx, 0, true);
            ea_done = true
        fi
    od;

WAIT_ACK:
    do
    /* APP send/recv allowed */
    :: (app_quota > 0) ->
        A2B_SEND(APP, tx, 0, true);
        app_quota--
    :: A_RECV(APP, e, kx, acc) ->
        if
        :: (e == rx) -> skip
        :: (retain_old && e == old_rx) -> skip
        :: else -> skip
        fi

    /* tolerate duplicate Resp (retransmit from responder) */
    :: A_RECV(Resp, e, kx, acc) -> skip

    /* Handle delayed/retransmitted Req while waiting for ACK (avoid head-of-line blocking). */
    :: A_RECV(Req, e, kx, acc) ->
        if
        :: !((e == rx) || (retain_old && e == old_rx)) -> skip
        :: else ->
            if
            :: (kx < local_kx) -> skip
            :: else -> unexpected = true; break
            fi
        fi

    /* Ignore any stray NKU (not expected in WAIT_ACK for initiator). */
    :: A_RECV(NKU, e, kx, acc) ->
        /* discard */
        skip

    :: A_RECV(PHAReq, e, kx, acc) -> A2B_SEND(PHAFin, tx, 0, true)
    :: A_RECV(PHAFin, e, kx, acc) -> skip
    :: A_RECV(EAReq, e, kx, acc) -> A2B_SEND(EAFin, tx, 0, true)
    :: A_RECV(EAFin, e, kx, acc) ->
        if
        :: ea_pending ->
            ea_pending = false;
            ea_done = true
        :: else ->
            A2B_SEND(ACK, tx, 0, true);
            ea_done = true
        fi

    /* retransmit NKU until ACK (only when no pending inbound message) */
    :: (!AUTH_PENDING && nku_retries > 0 && len(to_a) == 0) ->
        A2B_SEND(NKU, tx, 0, true);
        nku_retries--
    :: (!AUTH_PENDING && nku_retries == 0 && len(to_a) == 0) ->
        /* No further progress possible as initiator after bounded NKU retries. */
        abort_a = true;
        updating = false;
        break

    /* ACK completes initiator: bump tx to rx */
    :: A_RECV(ACK, e, kx, acc) ->
        if
        :: AUTH_PENDING -> skip
        :: (e == rx) ->
            tx = rx;
            retain_old = false;
            updating = false;
            assert(tx == rx);
            final_rx_a = rx;
            final_tx_a = tx;
            done_a = true;
            break
        :: else -> skip
        fi
    od;

ABORT_A:
    skip
}

proctype PeerB() priority 1
{
    byte rx = INIT_RX_B;
    byte tx = INIT_TX_B;
    byte old_rx = 255;
    bool retain_old = false;

    bool updating = false;
    bool initiated = false;
    bool derived = false; /* initiator derived EKU secrets (MUST NOT be deferred) */
    bool completed = false;
    byte local_kx = KX_B;
    byte peer_kx_active = 255;
    byte req_retries = REQ_RETRIES;
    byte nku_retries = NKU_RETRIES;
    byte resp_wait_retries = RESP_WAIT_RETRIES;
    byte app_quota = APP_QUOTA;
    byte e; byte kx; bool acc;

    if
    :: (INITIATE_B) ->
        atomic {
            updating = true;
            initiated = true;
            B2A_SEND(Req, tx, local_kx, true);
        }
    :: else -> skip
    fi;

WAIT_RESP:
    do
    :: (!AUTH_PENDING && deferred_req_b) ->
        if
        :: (!updating && (deferred_req_e_b == rx || (retain_old && deferred_req_e_b == old_rx))) ->
            updating = true;
            initiated = false;
            peer_kx_active = deferred_req_kx_b;
            B2A_SEND(Resp, tx, local_kx, true)
        :: else -> skip
        fi;
        deferred_req_b = false

    :: (ENABLE_PHA && PHA_TRIGGER_B && !pha_req_sent && !updating && !AUTH_PENDING) ->
        B2A_SEND(PHAReq, tx, 0, true);
        pha_pending = true;
        pha_req_sent = true
    :: (ENABLE_EA && EA_TRIGGER_B && !ea_req_sent_b && !updating && !AUTH_PENDING) ->
        B2A_SEND(EAReq, tx, 0, true);
        ea_pending = true;
        ea_req_sent_b = true
    :: (ENABLE_EA && EA_SPONT_TRIGGER_B && !ea_spont_sent_b && !updating && !AUTH_PENDING) ->
        /* spontaneous server authentication without prior request */
        B2A_SEND(EAFin, tx, 0, true);
        ea_spont_pending_b = true;
        ea_spont_sent_b = true

    :: (app_quota > 0) ->
        B2A_SEND(APP, tx, 0, true);
        app_quota--
    :: B_RECV(APP, e, kx, acc) ->
        if
        :: (e == rx) ->
            if
            :: retain_old -> retain_old = false
            :: else -> skip
            fi
        :: (retain_old && e == old_rx) -> skip
        :: else -> skip
        fi

    :: B_RECV(PHAFin, e, kx, acc) ->
        if
        :: pha_pending ->
            pha_pending = false;
            pha_done = true
        :: else -> skip
        fi
    :: B_RECV(EAReq, e, kx, acc) ->
        B2A_SEND(EAFin, tx, 0, true)
    :: B_RECV(EAFin, e, kx, acc) ->
        if
        :: ea_pending ->
            ea_pending = false;
            ea_done = true
        :: ea_spont_pending_b ->
            ea_spont_pending_b = false;
            ea_done = true
        :: else -> skip
        fi
    :: B_RECV(ACK, e, kx, acc) ->
        if
        :: ea_spont_pending_b ->
            ea_spont_pending_b = false;
            ea_done = true
        :: else -> skip
        fi

    :: (updating && initiated && req_retries > 0 && len(to_b) == 0) ->
        B2A_SEND(Req, tx, local_kx, true);
        req_retries--
    :: (updating && initiated && req_retries == 0 && len(to_b) == 0) ->
        /* No further progress possible as initiator after bounded Req retries. */
        abort_b = true;
        updating = false;
        goto ABORT_B
    /* waiting as responder for peer NKU: bounded timeout only if no inbound
       messages are pending anywhere on the inbound path (network + mailbox). */
    :: (updating && !initiated &&
        resp_wait_retries > 0 &&
        len(to_b) == 0 && len(a2b_p1) == 0 && len(a2b_p2) == 0) ->
        resp_wait_retries--
    :: (updating && !initiated &&
        resp_wait_retries == 0 &&
        len(to_b) == 0 && len(a2b_p1) == 0 && len(a2b_p2) == 0) ->
        abort_b = true;
        updating = false;
        goto ABORT_B

    :: B_RECV(Req, e, kx, acc) ->
        if
        :: AUTH_PENDING ->
            deferred_req_b = true;
            deferred_req_e_b = e;
            deferred_req_kx_b = kx;
            B2A_SEND(ACK, tx, 0, true)
        :: ((e == rx) || (retain_old && e == old_rx)) ->
            if
            :: (!updating) ->
                updating = true;
                initiated = false;
                peer_kx_active = kx;
                B2A_SEND(Resp, tx, local_kx, true);
            :: (initiated) ->
                if
                :: (kx < local_kx) -> skip
                :: (kx == local_kx) -> unexpected = true; break
                :: else ->
                    initiated = false;
                    peer_kx_active = kx;
                    B2A_SEND(Resp, tx, local_kx, true);
                fi
            :: else ->
                if
                :: (kx == peer_kx_active) -> B2A_SEND(Resp, tx, local_kx, true)
                :: else -> unexpected = true; break
                fi
            fi
        :: else ->
            skip
        fi

    :: B_RECV(Resp, e, kx, acc) ->
        if
        :: AUTH_PENDING -> skip
        :: (e != rx) -> skip
        :: (!updating || !initiated) -> skip
        :: else ->
            /* Derive secrets now (initiator MUST NOT defer); activate retention; bump rx */
            derived = true;
            old_rx = rx;
            retain_old = true;
            rx = rx + 1;
            B2A_SEND(NKU, tx, 0, true);
            goto WAIT_ACK
        fi

    :: B_RECV(NKU, e, kx, acc) ->
        if
        :: AUTH_PENDING -> skip
        :: !((e == rx) || (retain_old && e == old_rx)) -> skip
        :: (updating && !initiated && e == rx) ->
            old_rx = rx;
            retain_old = true;
            rx = rx + 1;
            tx = tx + 1;
            B2A_SEND(ACK, tx, 0, true);
            assert(tx == rx);
            updating = false;
            completed = true;
            final_rx_b = rx;
            final_tx_b = tx;
            done_b = true;
        :: (completed && retain_old && e == old_rx) ->
            B2A_SEND(ACK, tx, 0, true)
        :: else -> skip
        fi

    :: B_RECV(PHAReq, e, kx, acc) -> B2A_SEND(PHAFin, tx, 0, true)
    :: B_RECV(EAReq, e, kx, acc) -> B2A_SEND(EAFin, tx, 0, true)
    :: B_RECV(EAFin, e, kx, acc) ->
        if
        :: ea_pending ->
            ea_pending = false;
            ea_done = true
        :: ea_spont_pending_b ->
            ea_spont_pending_b = false;
            ea_done = true
        :: else -> skip
        fi
    :: B_RECV(ACK, e, kx, acc) ->
        if
        :: ea_spont_pending_b ->
            ea_spont_pending_b = false;
            ea_done = true
        :: else -> skip
        fi
    od;

WAIT_ACK:
    do
    :: (app_quota > 0) ->
        B2A_SEND(APP, tx, 0, true);
        app_quota--
    :: B_RECV(APP, e, kx, acc) ->
        if
        :: (e == rx) -> skip
        :: (retain_old && e == old_rx) -> skip
        :: else -> skip
        fi

    :: B_RECV(Resp, e, kx, acc) -> skip

    :: B_RECV(Req, e, kx, acc) ->
        if
        :: !((e == rx) || (retain_old && e == old_rx)) -> skip
        :: else ->
            if
            :: (kx < local_kx) -> skip
            :: else -> unexpected = true; break
            fi
        fi

    :: B_RECV(NKU, e, kx, acc) ->
        /* discard */
        skip

    :: B_RECV(PHAReq, e, kx, acc) -> B2A_SEND(PHAFin, tx, 0, true)
    :: B_RECV(PHAFin, e, kx, acc) -> skip
    :: B_RECV(EAReq, e, kx, acc) -> B2A_SEND(EAFin, tx, 0, true)
    :: B_RECV(EAFin, e, kx, acc) ->
        if
        :: ea_pending ->
            ea_pending = false;
            ea_done = true
        :: ea_spont_pending_b ->
            ea_spont_pending_b = false;
            ea_done = true
        :: else -> skip
        fi

    :: (!AUTH_PENDING && nku_retries > 0 && len(to_b) == 0) ->
        B2A_SEND(NKU, tx, 0, true);
        nku_retries--
    :: (!AUTH_PENDING && nku_retries == 0 && len(to_b) == 0) ->
        /* No further progress possible as initiator after bounded NKU retries. */
        abort_b = true;
        updating = false;
        break

    :: B_RECV(ACK, e, kx, acc) ->
        if
        :: ea_spont_pending_b ->
            ea_spont_pending_b = false;
            ea_done = true
        :: AUTH_PENDING -> skip
        :: (e == rx) ->
            tx = rx;
            retain_old = false;
            updating = false;
            assert(tx == rx);
            final_rx_b = rx;
            final_tx_b = tx;
            done_b = true;
            break
        :: else -> skip
        fi
    od;

ABORT_B:
    skip
}

init {
    atomic {
        run Network();
        run PeerA();
        run PeerB();
    }
}

/* --- LTL properties --- */
/* Liveness considers both success and bounded-failure termination. */
ltl no_deadlock { []( !unexpected -> <> ((done_a || abort_a) && (done_b || abort_b)) ) }
ltl no_unexpected { [](!unexpected) }
ltl epoch_consistency {
    [](
        (!unexpected && done_a && done_b) ->
        (final_tx_a == final_rx_a &&
         final_tx_b == final_rx_b &&
         final_tx_a == final_tx_b)
    )
}
