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
//   - Optional abstract post-handshake authentication (PHA) flow:
//       PHAReq (CertificateRequest-like) -> PHAFin (Finished-like)
//   - Optional abstract Exported Authenticator (EA, RFC 9261) flow:
//       EAReq (AuthenticatorRequest-like) -> EAFin (Authenticator-like)
//     triggered by application events, in both directions
//   - Optional spontaneous server authentication:
//       server sends EAFin without prior EAReq
//     with guards aligned to RFC 8446 Section 4.6.2 constraints:
//       * no PHA request while EKU is in progress
//       * no EKU request accepted while PHA is pending
//       * EKU requests observed during PHA are deferred and resumed after PHA
//       * no EKU epoch transition while PHA is pending
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

/* Optional PHA abstraction (disabled by default to preserve legacy runs). */
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

mtype = { Req, Resp, NKU, APP, PHAReq, PHAFin, EAReq, EAFin };

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
bool pha_pending = false;
bool pha_done = false;
bool pha_req_sent = false;
bool ea_pending = false;
bool ea_done = false;
bool ea_req_sent_a = false;
bool ea_req_sent_b = false;
bool ea_spont_pending = false;
bool ea_spont_sent_b = false;
bool deferred_req_a = false;
bool deferred_req_b = false;
byte deferred_kx_a = 255;
byte deferred_kx_b = 255;

#define AUTH_PENDING (pha_pending || ea_pending || ea_spont_pending)

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
    :: (!AUTH_PENDING && deferred_req_a) ->
        if
        :: (!updating) ->
            updating = true;
            initiated = false;
            peer_kx_active = deferred_kx_a;
            A2B_SEND(Resp, send_key, local_kx);
            send_key = send_key + 1
        :: else -> skip
        fi;
        deferred_req_a = false

    :: (ENABLE_PHA && PHA_TRIGGER_B && !pha_req_sent && !updating && !AUTH_PENDING) ->
        /* Abstract server-side post-handshake CertificateRequest. */
        B2A_SEND(PHAReq, send_key, 0);
        pha_pending = true;
        pha_req_sent = true
    :: (ENABLE_EA && EA_TRIGGER_A && !ea_req_sent_a && !updating && !AUTH_PENDING) ->
        /* Application-triggered Exported Authenticator request (A->B). */
        A2B_SEND(EAReq, send_key, 0);
        ea_pending = true;
        ea_req_sent_a = true

    :: (app_quota > 0) ->
        A2B_SEND(APP, send_key, 0);
        app_quota--

    :: A_RECV(APP, g, kx) ->
        assert(g == recv_key)

    :: A_RECV(PHAReq, g, kx) ->
        assert(g == recv_key);
        /* Defer EKU while PHA is outstanding. */
        A2B_SEND(PHAFin, send_key, 0)
    :: A_RECV(EAReq, g, kx) ->
        assert(g == recv_key);
        /* Respond with abstract Exported Authenticator. */
        A2B_SEND(EAFin, send_key, 0)
    :: A_RECV(EAFin, g, kx) ->
        assert(g == recv_key);
        if
        :: ea_pending ->
            ea_pending = false;
            ea_done = true
        :: ea_spont_pending ->
            ea_spont_pending = false;
            ea_done = true
        :: else -> skip
        fi

    :: A_RECV(Req, g, kx) ->
        assert(g == recv_key); /* EKU messages under old keys */
        if
        :: AUTH_PENDING ->
            deferred_req_a = true;
            deferred_kx_a = kx
        :: else ->
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
        fi

    :: A_RECV(Resp, g, kx) ->
        if
        :: AUTH_PENDING -> skip
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
        :: AUTH_PENDING -> skip
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
    :: (!AUTH_PENDING && deferred_req_b) ->
        if
        :: (!updating) ->
            updating = true;
            initiated = false;
            peer_kx_active = deferred_kx_b;
            B2A_SEND(Resp, send_key, local_kx);
            send_key = send_key + 1
        :: else -> skip
        fi;
        deferred_req_b = false

    :: (ENABLE_EA && EA_TRIGGER_B && !ea_req_sent_b && !updating && !AUTH_PENDING) ->
        /* Application-triggered Exported Authenticator request (B->A). */
        B2A_SEND(EAReq, send_key, 0);
        ea_pending = true;
        ea_req_sent_b = true
    :: (ENABLE_EA && EA_SPONT_TRIGGER_B && !ea_spont_sent_b && !updating && !AUTH_PENDING) ->
        /* Spontaneous server authentication without prior request. */
        B2A_SEND(EAFin, send_key, 0);
        ea_spont_pending = true;
        ea_spont_sent_b = true

    :: (app_quota > 0) ->
        B2A_SEND(APP, send_key, 0);
        app_quota--

    :: B_RECV(APP, g, kx) ->
        assert(g == recv_key)

    :: B_RECV(PHAFin, g, kx) ->
        assert(g == recv_key);
        if
        :: pha_pending ->
            pha_pending = false;
            pha_done = true
        :: else -> skip
        fi
    :: B_RECV(EAReq, g, kx) ->
        assert(g == recv_key);
        B2A_SEND(EAFin, send_key, 0)
    :: B_RECV(EAFin, g, kx) ->
        assert(g == recv_key);
        if
        :: ea_pending ->
            ea_pending = false;
            ea_done = true
        :: ea_spont_pending ->
            ea_spont_pending = false;
            ea_done = true
        :: else -> skip
        fi

    :: B_RECV(Req, g, kx) ->
        assert(g == recv_key);
        if
        :: AUTH_PENDING ->
            deferred_req_b = true;
            deferred_kx_b = kx
        :: else ->
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
        fi

    :: B_RECV(Resp, g, kx) ->
        if
        :: AUTH_PENDING -> skip
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
        :: AUTH_PENDING -> skip
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
