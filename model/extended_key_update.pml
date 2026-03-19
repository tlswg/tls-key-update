///////////////////////////////////////////////////////////////
// Extended Key Update (DTLS 1.3) - Single Initiator/Responder SPIN model
//
// Models Section 6 steps 1–7 and Appendix B.2.2/B.2.3:
//   Req -> Resp -> NKU -> ACK
//
// Includes:
//   - APP traffic at any time (bounded by quotas)
//   - loss + reordering via two paths each direction and a finite drop budget
//   - old epoch retention on the receive side per Appendix B.2.1/B.2.3
//   - optional abstract post-handshake authentication (PHA) interleaving:
//       PHAReq -> PHAFin (RFC 8446 Section 4.6.2-inspired guardrails)
//       with deferred EKU processing until PHA completion
//   - optional abstract Exported Authenticator (RFC 9261):
//       EAReq -> EAFin (application-triggered)
//   - optional spontaneous server authentication:
//       responder sends EAFin without prior EAReq; initiator ACKs it
//
// Intentionally out-of-scope:
//   - the optional "defer Resp under load and ACK the Req" path (Section 6 step 2)
//   - classic DTLS KeyUpdate interaction
///////////////////////////////////////////////////////////////

/* --- Configuration knobs (override via spin -D...) --- */
#ifndef INIT_RX_I
#define INIT_RX_I 0
#endif
#ifndef INIT_TX_I
#define INIT_TX_I 0
#endif
#ifndef INIT_RX_R
#define INIT_RX_R 0
#endif
#ifndef INIT_TX_R
#define INIT_TX_R 0
#endif

#ifndef DROPS
#define DROPS 2
#endif
#ifndef REQ_RETRIES
#define REQ_RETRIES 4
#endif
#ifndef NKU_RETRIES
#define NKU_RETRIES 4
#endif
#ifndef APP_QUOTA_I
#define APP_QUOTA_I 0
#endif
#ifndef APP_QUOTA_R
#define APP_QUOTA_R 0
#endif
#ifndef ENABLE_PHA
#define ENABLE_PHA 0
#endif
#ifndef PHA_TRIGGER_R
#define PHA_TRIGGER_R 1
#endif
#ifndef ENABLE_EA
#define ENABLE_EA 0
#endif
#ifndef EA_TRIGGER_I
#define EA_TRIGGER_I 1
#endif
#ifndef EA_TRIGGER_R
#define EA_TRIGGER_R 1
#endif
#ifndef EA_SPONT_TRIGGER_R
#define EA_SPONT_TRIGGER_R 1
#endif

mtype = { Req, Resp, NKU, ACK, APP, PHAReq, PHAFin, EAReq, EAFin };

/* Visible delivery channels (post-network): (type, tag_epoch, accepted) */
chan to_responder = [8] of { mtype, byte, bool };
chan to_initiator = [8] of { mtype, byte, bool };

/* Hidden network paths (for reordering): (type, tag_epoch, accepted) */
chan i2r_p1 = [4] of { mtype, byte, bool };
chan i2r_p2 = [4] of { mtype, byte, bool };
chan r2i_p1 = [4] of { mtype, byte, bool };
chan r2i_p2 = [4] of { mtype, byte, bool };

byte drops_left = DROPS;

#define I2R_SEND(t,e,a)  if :: i2r_p1!t,e,a :: i2r_p2!t,e,a fi
#define R2I_SEND(t,e,a)  if :: r2i_p1!t,e,a :: r2i_p2!t,e,a fi
#define I_RECV(t,e,a)    to_initiator ? t,e,a
#define R_RECV(t,e,a)    to_responder ? t,e,a

/* --- Global markers (properties) --- */
bool done_i = false;
bool done_r = false;
bool unexpected = false;
bool pha_pending = false;
bool pha_done = false;
bool pha_req_sent = false;
bool ea_pending = false;
bool ea_done = false;
bool ea_req_sent_i = false;
bool ea_req_sent_r = false;
bool ea_spont_pending_r = false;
bool ea_spont_sent_r = false;
bool deferred_req_r = false;
byte deferred_req_epoch_r = 255;

#define AUTH_PENDING (pha_pending || ea_pending || ea_spont_pending_r)

byte final_rx_i = 255;
byte final_tx_i = 255;
byte final_rx_r = 255;
byte final_tx_r = 255;

/* --- Global state (epochs/retention) --- */
byte rx_epoch_i = INIT_RX_I;
byte tx_epoch_i = INIT_TX_I;
bool updating_i = false;
byte req_retries = REQ_RETRIES;
byte nku_retries = NKU_RETRIES;
byte app_quota_i = APP_QUOTA_I;
byte old_rx_i = 255;
bool retain_old_i = false;

byte rx_epoch_r = INIT_RX_R;
byte tx_epoch_r = INIT_TX_R;
bool updating_r = false;
byte app_quota_r = APP_QUOTA_R;
byte old_rx_r = 255;
bool retain_old_r = false;

inline APP_ACCEPT(assert_epoch, assert_old, assert_retain) {
    assert( (assert_epoch) || ((assert_retain) && (assert_old)) )
}

inline ACTIVE_EPOCH_ASSERTS() {
    /* Epoch mismatches are allowed while an update is in progress. */
    assert( (tx_epoch_i == rx_epoch_r) || updating_i || updating_r );
    assert( (tx_epoch_r == rx_epoch_i) || updating_i || updating_r );
}

/* --- Network process: Loss + Reordering --- */
proctype Network() priority 2 {
    mtype t; byte e; bool a;
    do
    :: (done_i && done_r &&
        len(i2r_p1) == 0 && len(i2r_p2) == 0 &&
        len(r2i_p1) == 0 && len(r2i_p2) == 0) -> break

    :: (len(i2r_p1) > 0) ->
        i2r_p1 ? t,e,a;
        if
        :: (drops_left > 0) -> drops_left--
        :: to_responder ! t,e,a
        fi
    :: (len(i2r_p2) > 0) ->
        i2r_p2 ? t,e,a;
        if
        :: (drops_left > 0) -> drops_left--
        :: to_responder ! t,e,a
        fi
    :: (len(r2i_p1) > 0) ->
        r2i_p1 ? t,e,a;
        if
        :: (drops_left > 0) -> drops_left--
        :: to_initiator ! t,e,a
        fi
    :: (len(r2i_p2) > 0) ->
        r2i_p2 ? t,e,a;
        if
        :: (drops_left > 0) -> drops_left--
        :: to_initiator ! t,e,a
        fi
    :: else -> skip
    od
}

/* --- Initiator (Appendix B.2.2) --- */
proctype Initiator() priority 1
{
    byte e; bool acc;
    byte old_tx_i = 255;

    updating_i = true;
    old_tx_i = tx_epoch_i;
    I2R_SEND(Req, tx_epoch_i, true);
    ACTIVE_EPOCH_ASSERTS();

WAIT_RESP:
    do
    :: (ENABLE_EA && EA_TRIGGER_I && !ea_req_sent_i && !updating_i && !AUTH_PENDING) ->
        I2R_SEND(EAReq, tx_epoch_i, true);
        ea_pending = true;
        ea_req_sent_i = true;
        ACTIVE_EPOCH_ASSERTS()

    /* APP send anytime */
    :: (app_quota_i > 0) ->
        I2R_SEND(APP, tx_epoch_i, true);
        app_quota_i--;
        ACTIVE_EPOCH_ASSERTS()

    /* APP receive anytime */
    :: I_RECV(APP, e, acc) ->
        APP_ACCEPT(e == rx_epoch_i, e == old_rx_i, retain_old_i);
        ACTIVE_EPOCH_ASSERTS()

    /* abstract client-side PHA response */
    :: I_RECV(PHAReq, e, acc) ->
        I2R_SEND(PHAFin, tx_epoch_i, true);
        ACTIVE_EPOCH_ASSERTS()
    :: I_RECV(EAReq, e, acc) ->
        I2R_SEND(EAFin, tx_epoch_i, true);
        ACTIVE_EPOCH_ASSERTS()
    :: I_RECV(EAFin, e, acc) ->
        if
        :: ea_pending ->
            ea_pending = false;
            ea_done = true
        :: else ->
            /* spontaneous server EA is acknowledged in DTLS */
            I2R_SEND(ACK, tx_epoch_i, true);
            ea_done = true
        fi;
        ACTIVE_EPOCH_ASSERTS()

    /* retransmit Req while waiting (only when no pending inbound message) */
    :: (!AUTH_PENDING && updating_i && req_retries > 0 && len(to_initiator) == 0) ->
        I2R_SEND(Req, tx_epoch_i, true);
        req_retries--;
        ACTIVE_EPOCH_ASSERTS()

    /* receive Resp (implicit ACK of Req) */
    :: I_RECV(Resp, e, acc) ->
        if
        :: AUTH_PENDING -> skip
        :: (e != rx_epoch_i) -> skip
        :: (!acc) -> unexpected = true; break
        :: else ->
            /* Step 3: activate retention + bump rx; MUST NOT defer sending NKU. */
            old_rx_i = rx_epoch_i;
            retain_old_i = true;
            rx_epoch_i = rx_epoch_i + 1;
            I2R_SEND(NKU, old_tx_i, true);
            ACTIVE_EPOCH_ASSERTS();
            goto WAIT_ACK
        fi

    /* deferred-request ACK while PHA is outstanding */
    :: I_RECV(ACK, e, acc) -> skip
    od;

WAIT_ACK:
    do
    /* APP send/recv allowed */
    :: (app_quota_i > 0) ->
        I2R_SEND(APP, tx_epoch_i, true);
        app_quota_i--;
        ACTIVE_EPOCH_ASSERTS()

    :: I_RECV(APP, e, acc) ->
        APP_ACCEPT(e == rx_epoch_i, e == old_rx_i, retain_old_i);
        if
        :: (retain_old_i && e == rx_epoch_i) -> retain_old_i = false
        :: else -> skip
        fi;
        ACTIVE_EPOCH_ASSERTS()

    /* tolerate duplicate Resp */
    :: I_RECV(Resp, e, acc) -> skip

    /* ignore any stray Req/NKU */
    :: I_RECV(Req, e, acc) -> skip
    :: I_RECV(NKU, e, acc) -> skip
    :: I_RECV(PHAReq, e, acc) -> I2R_SEND(PHAFin, tx_epoch_i, true)
    :: I_RECV(PHAFin, e, acc) -> skip
    :: I_RECV(EAReq, e, acc) -> I2R_SEND(EAFin, tx_epoch_i, true)
    :: I_RECV(EAFin, e, acc) ->
        if
        :: ea_pending ->
            ea_pending = false;
            ea_done = true
        :: else ->
            I2R_SEND(ACK, tx_epoch_i, true);
            ea_done = true
        fi

    /* retransmit NKU until ACK (only when no pending inbound message) */
    :: (!AUTH_PENDING && nku_retries > 0 && len(to_initiator) == 0) ->
        I2R_SEND(NKU, old_tx_i, true);
        nku_retries--;
        ACTIVE_EPOCH_ASSERTS()

    /* ACK completes initiator: tx := rx */
    :: I_RECV(ACK, e, acc) ->
        if
        :: AUTH_PENDING -> skip
        :: (e == rx_epoch_i) ->
            tx_epoch_i = rx_epoch_i;
            retain_old_i = false;
            updating_i = false;
            assert(tx_epoch_i == rx_epoch_i);
            final_rx_i = rx_epoch_i;
            final_tx_i = tx_epoch_i;
            done_i = true;
            ACTIVE_EPOCH_ASSERTS();
            break
        :: else -> skip
        fi
    od
}

/* --- Responder (Appendix B.2.3) --- */
proctype Responder() priority 1
{
    byte e; bool aux;

    do
    :: (!AUTH_PENDING && deferred_req_r) ->
        if
        :: (deferred_req_epoch_r == rx_epoch_r) ->
            updating_r = true;
            R2I_SEND(Resp, tx_epoch_r, true)
        :: else -> skip
        fi;
        deferred_req_r = false;
        ACTIVE_EPOCH_ASSERTS()

    /* abstract server-side PHA request */
    :: (ENABLE_PHA && PHA_TRIGGER_R && !pha_req_sent && !updating_r && !AUTH_PENDING) ->
        R2I_SEND(PHAReq, tx_epoch_r, true);
        pha_pending = true;
        pha_req_sent = true;
        ACTIVE_EPOCH_ASSERTS()
    :: (ENABLE_EA && EA_TRIGGER_R && !ea_req_sent_r && !updating_r && !AUTH_PENDING) ->
        R2I_SEND(EAReq, tx_epoch_r, true);
        ea_pending = true;
        ea_req_sent_r = true;
        ACTIVE_EPOCH_ASSERTS()
    :: (ENABLE_EA && EA_SPONT_TRIGGER_R && !ea_spont_sent_r && !updating_r && !AUTH_PENDING) ->
        /* Spontaneous server authentication without prior request. */
        R2I_SEND(EAFin, tx_epoch_r, true);
        ea_spont_pending_r = true;
        ea_spont_sent_r = true;
        ACTIVE_EPOCH_ASSERTS()

    /* APP send anytime */
    :: (app_quota_r > 0) ->
        R2I_SEND(APP, tx_epoch_r, true);
        app_quota_r--;
        ACTIVE_EPOCH_ASSERTS()

    /* APP receive anytime */
    :: R_RECV(APP, e, aux) ->
        APP_ACCEPT(e == rx_epoch_r, e == old_rx_r, retain_old_r);
        if
        :: (retain_old_r && e == rx_epoch_r) -> retain_old_r = false
        :: else -> skip
        fi;
        ACTIVE_EPOCH_ASSERTS()

    /* abstract server-side PHA completion */
    :: R_RECV(PHAFin, e, aux) ->
        if
        :: pha_pending ->
            pha_pending = false;
            pha_done = true
        :: else -> skip
        fi;
        ACTIVE_EPOCH_ASSERTS()
    :: R_RECV(EAFin, e, aux) ->
        if
        :: ea_pending ->
            ea_pending = false;
            ea_done = true
        :: else -> skip
        fi;
        ACTIVE_EPOCH_ASSERTS()
    :: R_RECV(EAReq, e, aux) ->
        R2I_SEND(EAFin, tx_epoch_r, true);
        ACTIVE_EPOCH_ASSERTS()
    :: R_RECV(ACK, e, aux) ->
        if
        :: ea_spont_pending_r ->
            ea_spont_pending_r = false;
            ea_done = true
        :: else -> skip
        fi;
        ACTIVE_EPOCH_ASSERTS()

    /* Req starts update */
    :: R_RECV(Req, e, aux) ->
        if
        :: AUTH_PENDING ->
            deferred_req_r = true;
            deferred_req_epoch_r = e;
            /* deferred-request ACK in DTLS mode */
            R2I_SEND(ACK, tx_epoch_r, true)
        :: (e != rx_epoch_r) -> skip
        :: else ->
            updating_r = true;
            R2I_SEND(Resp, tx_epoch_r, true);
            ACTIVE_EPOCH_ASSERTS()
        fi

    /* NKU triggers epoch/key update */
    :: R_RECV(NKU, e, aux) ->
        if
        :: AUTH_PENDING -> skip
        :: (!updating_r && !retain_old_r) -> skip
        :: (updating_r && e == rx_epoch_r) ->
            old_rx_r = rx_epoch_r;
            retain_old_r = true;
            rx_epoch_r = rx_epoch_r + 1;
            tx_epoch_r = tx_epoch_r + 1;
            assert(tx_epoch_r == rx_epoch_r);
            R2I_SEND(ACK, tx_epoch_r, true);
            updating_r = false;
            final_rx_r = rx_epoch_r;
            final_tx_r = tx_epoch_r;
            done_r = true;
            ACTIVE_EPOCH_ASSERTS()
        :: (retain_old_r && e == old_rx_r) ->
            /* duplicate NKU after lost ACK: retransmit ACK */
            R2I_SEND(ACK, tx_epoch_r, true)
        :: else ->
            skip
        fi
    od
}

init {
    atomic {
        run Network();
        run Initiator();
        run Responder();
    }
}

ltl no_unexpected { [](!unexpected) }
ltl epoch_consistency {
    [](
        (!unexpected && done_i && done_r) ->
        (final_tx_i == final_rx_i &&
         final_tx_r == final_rx_r &&
         final_tx_i == final_tx_r)
    )
}
