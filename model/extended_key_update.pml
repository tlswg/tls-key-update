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

mtype = { Req, Resp, NKU, ACK, APP };

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
    /* APP send anytime */
    :: (app_quota_i > 0) ->
        I2R_SEND(APP, tx_epoch_i, true);
        app_quota_i--;
        ACTIVE_EPOCH_ASSERTS()

    /* APP receive anytime */
    :: I_RECV(APP, e, acc) ->
        APP_ACCEPT(e == rx_epoch_i, e == old_rx_i, retain_old_i);
        ACTIVE_EPOCH_ASSERTS()

    /* retransmit Req while waiting (only when no pending inbound message) */
    :: (updating_i && req_retries > 0 && len(to_initiator) == 0) ->
        I2R_SEND(Req, tx_epoch_i, true);
        req_retries--;
        ACTIVE_EPOCH_ASSERTS()

    /* receive Resp (implicit ACK of Req) */
    :: I_RECV(Resp, e, acc) ->
        if
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

    /* retransmit NKU until ACK (only when no pending inbound message) */
    :: (nku_retries > 0 && len(to_initiator) == 0) ->
        I2R_SEND(NKU, old_tx_i, true);
        nku_retries--;
        ACTIVE_EPOCH_ASSERTS()

    /* ACK completes initiator: tx := rx */
    :: I_RECV(ACK, e, acc) ->
        if
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

    /* Req starts update */
    :: R_RECV(Req, e, aux) ->
        if
        :: (e != rx_epoch_r) -> skip
        :: else ->
            updating_r = true;
            R2I_SEND(Resp, tx_epoch_r, true);
            ACTIVE_EPOCH_ASSERTS()
        fi

    /* NKU triggers epoch/key update */
    :: R_RECV(NKU, e, aux) ->
        if
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
