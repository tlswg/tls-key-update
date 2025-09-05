///////////////////////////////////////////////////////////////
// Extended Key Update
// + APP (app_data) transmission anytime
// + Old key retention to deal with packet loss and reordering
// + Network behavior considering loss (drops_left)and reordering (2 paths per direction)
// Messages carry only the sender's TX-epoch tag.
// Allows INITIATOR rx,tx epoch to start unequal.
// Initiator bump rule on R's NKU: let N = old_tx + 1; set tx=N; rx=N; send ACK.
///////////////////////////////////////////////////////////////

/*
Configuration: initial epochs (may be unequal)
------------------------------------------------------
To keep cross-peer compatibility at t=0 you should set:
  INIT_TX_I == INIT_RX_R    (for I -> R acceptance)
  INIT_TX_R == INIT_RX_I    (for R -> I acceptance)
Defaults below use equal values for simplicity.
*/
byte INIT_RX_I = 0;
byte INIT_TX_I = 0;
byte INIT_RX_R = 0;
byte INIT_TX_R = 0;

mtype = { Req, Resp, NKU, ACK, APP };   // APP = app_data

///////////////////////////////////////////////////////////////
// Visible delivery channels (post-network)
///////////////////////////////////////////////////////////////
chan to_responder = [8] of { mtype, byte, bool };
chan to_initiator = [8] of { mtype, byte, bool };

///////////////////////////////////////////////////////////////
// Hidden network paths (for reordering)
///////////////////////////////////////////////////////////////
chan i2r_p1 = [4] of { mtype, byte, bool };
chan i2r_p2 = [4] of { mtype, byte, bool };
chan r2i_p1 = [4] of { mtype, byte, bool };
chan r2i_p2 = [4] of { mtype, byte, bool };

byte drops_left = 2;   // number of allowed drops (0 => no loss)

///////////////////////////////////////////////////////////////
// Convenience macros for peers
///////////////////////////////////////////////////////////////
#define I2R_SEND(t,e,a)  if :: i2r_p1!t,e,a :: i2r_p2!t,e,a fi
#define R2I_SEND(t,e,a)  if :: r2i_p1!t,e,a :: r2i_p2!t,e,a fi
#define I_RECV(t,e,a)    to_initiator ? t,e,a
#define R_RECV(t,e,a)    to_responder ? t,e,a

///////////////////////////////////////////////////////////////
// Network process: Loss + Reordering
///////////////////////////////////////////////////////////////
proctype Network() {
    mtype t; byte e; bool a;
    do
    :: (len(i2r_p1) > 0) ->
        i2r_p1 ? t,e,a;
        if
        :: (drops_left > 0) -> drops_left--       /* drop */
        :: to_responder ! t,e,a                   /* deliver */
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

///////////////////////////////////////////////////////////////
// Global state
///////////////////////////////////////////////////////////////
// Initiator
byte rx_epoch_i = INIT_RX_I;    // inbound accepted epoch
byte tx_epoch_i = INIT_TX_I;    // outbound used epoch
bool updating_i = false;
bool derived_i  = false;        // after accepted Response
byte app_quota_i = 2;           // limit for extra APP sends

byte old_epoch_i = 255;         // old RX epoch (retention)
bool retain_old_i = false;

// Responder
byte rx_epoch_r = INIT_RX_R;
byte tx_epoch_r = INIT_TX_R;
bool updating_r = false;
bool accepted_r = false;
byte app_quota_r = 2;

byte old_epoch_r = 255;         // old RX epoch (retention)
bool retain_old_r = false;

///////////////////////////////////////////////////////////////
// Global assertion: active epochs per direction must match.
// Mismatch is allowed while the responder is updating.
///////////////////////////////////////////////////////////////
inline ACTIVE_EPOCH_ASSERTS() {
    /* I -> R: mismatch allowed while R updates */
    assert( (tx_epoch_i == rx_epoch_r) || updating_r );

    /* R -> I: mismatch allowed while R updates (R may have raised RX already) */
    assert( (tx_epoch_r == rx_epoch_i) || updating_r );
}

///////////////////////////////////////////////////////////////
// Initiator
///////////////////////////////////////////////////////////////
proctype Initiator()
{
    byte e_resp, e_nku, e_ack, e_app;
    bool acc, aux;
    byte N_i; /* temporary for new epoch derived from old tx */

    // (1) Start: ExtendedKeyUpdateRequest
    updating_i = true;
    I2R_SEND(Req, tx_epoch_i, true);
    ACTIVE_EPOCH_ASSERTS();

    do
    /* --- APP sends from I at any time --- */
    :: (app_quota_i > 0) ->
        I2R_SEND(APP, tx_epoch_i, true);
        app_quota_i--;
        ACTIVE_EPOCH_ASSERTS()

    /* --- APP receives at I at any time --- */
    :: I_RECV(APP, e_app, aux) ->
        /* accept new RX or (during retention) old RX */
        assert( (e_app == rx_epoch_i) || (retain_old_i && e_app == old_epoch_i) );
        if
        :: (retain_old_i && e_app == rx_epoch_i) -> retain_old_i = false
        :: else -> skip
        fi
        ACTIVE_EPOCH_ASSERTS()

    /* --- Protocol: Response --- */
    :: I_RECV(Resp, e_resp, acc) ->
        assert(e_resp == rx_epoch_i);
        if
        :: acc ->
            derived_i = true;                 // (4)
            I2R_SEND(NKU, tx_epoch_i, true);  // (5) tag = old TX
            ACTIVE_EPOCH_ASSERTS()
        :: else ->
            updating_i = false;
            ACTIVE_EPOCH_ASSERTS();
            break
        fi

    /* --- Protocol: NKU from Responder --- */
    :: I_RECV(NKU, e_nku, aux) ->
        assert(e_nku == rx_epoch_i);          // R still tags with old TX
        /* Activate retention */
        old_epoch_i  = rx_epoch_i;
        retain_old_i = true;

        /* Derive new keys and epoch */
        N_i = tx_epoch_i + 1;
        tx_epoch_i = N_i;
        rx_epoch_i = N_i;

        /* (9) Final ACK (tag = current tx, which equals new rx now) */
        I2R_SEND(ACK, tx_epoch_i, true);

        assert(tx_epoch_i == rx_epoch_i);
        updating_i = false;
        ACTIVE_EPOCH_ASSERTS();
        break
    od
}

///////////////////////////////////////////////////////////////
// Responder
///////////////////////////////////////////////////////////////
proctype Responder()
{
    byte e_req, e_nku, e_ack, e_app;
    bool aux;

    do
    /* --- APP sends from R at any time --- */
    :: (app_quota_r > 0) ->
        R2I_SEND(APP, tx_epoch_r, true);
        app_quota_r--;
        ACTIVE_EPOCH_ASSERTS()

    /* --- APP receives at R at any time --- */
    :: R_RECV(APP, e_app, aux) ->
        assert( (e_app == rx_epoch_r) || (retain_old_r && e_app == old_epoch_r) );
        if
        :: (retain_old_r && e_app == rx_epoch_r) -> retain_old_r = false
        :: else -> skip
        fi
        ACTIVE_EPOCH_ASSERTS()

    /* --- Protocol: Request --- */
    :: R_RECV(Req, e_req, aux) ->
        assert(e_req == rx_epoch_r);
        updating_r = true;

        if
        :: R2I_SEND(Resp, tx_epoch_r, true) ->
            accepted_r = true;
            ACTIVE_EPOCH_ASSERTS()
        :: R2I_SEND(Resp, tx_epoch_r, false) ->
            updating_r = false;
            ACTIVE_EPOCH_ASSERTS();
            break
        fi

    /* --- Protocol: NKU from Initiator --- */
    :: R_RECV(NKU, e_nku, aux) ->
        assert(updating_r && accepted_r);
        assert(e_nku == rx_epoch_r);          // I still tags with old TX

        /* Activate retention */
        old_epoch_r  = rx_epoch_r;
        retain_old_r = true;

        /* Raise RX to new epoch (TX stays old for one more flight) */
        rx_epoch_r = rx_epoch_r + 1;

        /* (7) Own NKU (tag = old TX) */
        R2I_SEND(NKU, tx_epoch_r, true);
        ACTIVE_EPOCH_ASSERTS()

    /* --- Protocol: final ACK from Initiator --- */
    :: R_RECV(ACK, e_ack, aux) ->
        assert(e_ack == rx_epoch_r);          // ACK arrives under new epoch
        tx_epoch_r = rx_epoch_r;              // now switch TX
        retain_old_r = false;                 // retention ends safely
        assert(tx_epoch_r == rx_epoch_r);
        updating_r = false;
        ACTIVE_EPOCH_ASSERTS();
        break
    od
}

///////////////////////////////////////////////////////////////
// System start
///////////////////////////////////////////////////////////////
init {
    atomic {
        run Network();
        run Initiator();
        run Responder();
    }
}
