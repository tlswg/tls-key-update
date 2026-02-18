///////////////////////////////////////////////////////////////
// TLS 1.3 Extended Key Update (EKU) - SPIN/Promela model
//
// Models Section 5 (TLS 1.3 considerations) and Appendix B.1:
//   Req  -> Resp -> NKU
//
// Key points reflected:
//   - All EKU handshake messages are encrypted under OLD send keys.
//   - Responder updates SEND keys after sending Resp.
//   - Initiator updates RECEIVE keys on Resp, sends NKU under old keys,
//     then updates SEND keys after sending NKU.
//   - Crossed requests rule: compare KeyShareEntry.key_exchange values
//     (abstracted as KX_A/KX_B):
//       peer < local  => ignore
//       peer == local => abort ("unexpected_message")
//       peer > local  => abandon local initiation; act as responder
//
// Optional APP traffic can be enabled to sanity-check acceptance under
// the current receive key generation (no DTLS-like retention in TLS).
///////////////////////////////////////////////////////////////

#ifndef E
#define E 0
#endif

/* Both peers may initiate (set one to 0 to disable). */
#ifndef INITIATE_A
#define INITIATE_A 1
#endif
#ifndef INITIATE_B
#define INITIATE_B 1
#endif

/* KeyShareEntry.key_exchange values used for crossed-requests tie-break. */
#ifndef KX_A
#define KX_A 10
#endif
#ifndef KX_B
#define KX_B 20
#endif

/* Reduce state space: set to 0 for no APP traffic. */
#ifndef APP_QUOTA
#define APP_QUOTA 0
#endif

mtype = { Req, Resp, NKU, APP };

/* (type, key_generation_tag, key_exchange) */
chan a2b = [2] of { mtype, byte, byte };
chan b2a = [2] of { mtype, byte, byte };

#define A2B_SEND(t,g,kx) a2b ! t,g,kx
#define B2A_SEND(t,g,kx) b2a ! t,g,kx
#define A_RECV(t,g,kx)   b2a ? t,g,kx
#define B_RECV(t,g,kx)   a2b ? t,g,kx

bool done_a = false;
bool done_b = false;
bool unexpected = false;

byte final_send_a = 255;
byte final_recv_a = 255;
byte final_send_b = 255;
byte final_recv_b = 255;

proctype PeerA() priority 1
{
    byte send_key = E;
    byte recv_key = E;
    bool updating = false;
    bool initiated = false;
    byte local_kx = KX_A;
    byte peer_kx_active = 255;
    byte app_quota = APP_QUOTA;

    mtype t; byte g; byte kx;

    if
    :: (INITIATE_A) ->
        atomic {
            updating = true;
            initiated = true;
            A2B_SEND(Req, send_key, local_kx);
        }
    :: else -> skip
    fi;

MAIN:
    do
    :: (app_quota > 0) ->
        A2B_SEND(APP, send_key, 0);
        app_quota--

    :: A_RECV(APP, g, kx) ->
        assert(g == recv_key)

    :: A_RECV(Req, g, kx) ->
        assert(g == recv_key); /* EKU messages under old keys */
        if
        :: (!updating) ->
            updating = true;
            initiated = false;
            peer_kx_active = kx;
            /* Send Resp under old send_key, then update SEND keys. */
            A2B_SEND(Resp, send_key, local_kx);
            send_key = send_key + 1
        :: (initiated) ->
            /* Crossed-requests rule (Appendix B.1.1). */
            if
            :: (kx < local_kx) -> skip
            :: (kx == local_kx) -> unexpected = true; break
            :: else ->
                /* Abandon local initiation; act as responder. */
                initiated = false;
                peer_kx_active = kx;
                A2B_SEND(Resp, send_key, local_kx);
                send_key = send_key + 1
            fi
        :: else ->
            /* Duplicate Req while acting as responder: tolerate only if same key_exchange. */
            if
            :: (kx == peer_kx_active) -> A2B_SEND(Resp, send_key, local_kx)
            :: else -> unexpected = true; break
            fi
        fi

    :: A_RECV(Resp, g, kx) ->
        if
        :: (!updating || !initiated) -> skip
        :: (g != recv_key) -> skip
        :: else ->
            /* Step 4: update RECEIVE keys, then send NKU under OLD send keys. */
            recv_key = recv_key + 1;
            A2B_SEND(NKU, send_key, 0);
            /* Step 5: update SEND keys after sending NKU. */
            send_key = send_key + 1;
            updating = false;
            initiated = false;
            final_send_a = send_key;
            final_recv_a = recv_key;
            done_a = true;
            break
        fi

    :: A_RECV(NKU, g, kx) ->
        if
        :: (!updating || initiated) -> skip
        :: (g != recv_key) -> unexpected = true; break
        :: else ->
            /* Step 6: responder updates RECEIVE keys on NKU. */
            recv_key = recv_key + 1;
            updating = false;
            final_send_a = send_key;
            final_recv_a = recv_key;
            done_a = true;
            break
        fi
    od;

    /* Success states: keys are synchronized (both advanced by 1). */
    if
    :: (!unexpected && done_a) -> assert(send_key == E+1 && recv_key == E+1)
    :: else -> skip
    fi
}

proctype PeerB() priority 1
{
    byte send_key = E;
    byte recv_key = E;
    bool updating = false;
    bool initiated = false;
    byte local_kx = KX_B;
    byte peer_kx_active = 255;
    byte app_quota = APP_QUOTA;

    mtype t; byte g; byte kx;

    if
    :: (INITIATE_B) ->
        atomic {
            updating = true;
            initiated = true;
            B2A_SEND(Req, send_key, local_kx);
        }
    :: else -> skip
    fi;

MAIN:
    do
    :: (app_quota > 0) ->
        B2A_SEND(APP, send_key, 0);
        app_quota--

    :: B_RECV(APP, g, kx) ->
        assert(g == recv_key)

    :: B_RECV(Req, g, kx) ->
        assert(g == recv_key);
        if
        :: (!updating) ->
            updating = true;
            initiated = false;
            peer_kx_active = kx;
            B2A_SEND(Resp, send_key, local_kx);
            send_key = send_key + 1
        :: (initiated) ->
            if
            :: (kx < local_kx) -> skip
            :: (kx == local_kx) -> unexpected = true; break
            :: else ->
                initiated = false;
                peer_kx_active = kx;
                B2A_SEND(Resp, send_key, local_kx);
                send_key = send_key + 1
            fi
        :: else ->
            if
            :: (kx == peer_kx_active) -> B2A_SEND(Resp, send_key, local_kx)
            :: else -> unexpected = true; break
            fi
        fi

    :: B_RECV(Resp, g, kx) ->
        if
        :: (!updating || !initiated) -> skip
        :: (g != recv_key) -> skip
        :: else ->
            recv_key = recv_key + 1;
            B2A_SEND(NKU, send_key, 0);
            send_key = send_key + 1;
            updating = false;
            initiated = false;
            final_send_b = send_key;
            final_recv_b = recv_key;
            done_b = true;
            break
        fi

    :: B_RECV(NKU, g, kx) ->
        if
        :: (!updating || initiated) -> skip
        :: (g != recv_key) -> unexpected = true; break
        :: else ->
            recv_key = recv_key + 1;
            updating = false;
            final_send_b = send_key;
            final_recv_b = recv_key;
            done_b = true;
            break
        fi
    od;

    if
    :: (!unexpected && done_b) -> assert(send_key == E+1 && recv_key == E+1)
    :: else -> skip
    fi
}

init {
    atomic {
        run PeerA();
        run PeerB();
    }
}

ltl no_unexpected { [](!unexpected) }
ltl key_sync {
    [](
        (!unexpected && done_a && done_b) ->
        (final_send_a == final_recv_a &&
         final_send_b == final_recv_b &&
         final_send_a == final_send_b)
    )
}
