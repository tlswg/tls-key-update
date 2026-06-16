///////////////////////////////////////////////////////////////
// TLS 1.3 Extended Key Update (EKU) - SPIN/Promela model
//
// Models Section 5 (TLS 1.3 considerations) and Appendix B.1:
//   Req  -> Resp -> Fin
//
// Key points reflected:
//   - All EKU handshake messages are encrypted under OLD send keys.
//   - Responder updates SEND keys after sending Resp.
//   - Initiator updates RECEIVE keys on Resp, sends Fin under old keys,
//     then updates SEND keys after sending Fin.
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
//   - EA is intentionally not serialized with EKU; the current specification
//     makes the EA API epoch-aware and imposes no EKU/EA serialization rule.
//   - Optional invalid-message injection (disabled by default) covers:
//       classic KeyUpdate, unknown EKU subtype, EKU before Finished, and
//       wrong KeyShareEntry group.
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
#ifndef INJECT_ERRORS
#define INJECT_ERRORS 0
#endif

mtype = {
    Req, Resp, Fin, APP, PHAReq, PHAFin, EAReq, EAFin,
    KeyUpdate, UnknownEKU, EarlyEKU, BadGroupReq, BadGroupResp
};

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
bool illegal_parameter = false;
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

#define PHA_PENDING (pha_pending)

byte final_send_a = 255;
byte final_receive_a = 255;
byte final_send_b = 255;
byte final_receive_b = 255;

proctype PeerA() priority 1
{
    byte send_key = E;
    byte receive_key = E;
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
    :: (!PHA_PENDING && deferred_req_a) ->
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

    :: (ENABLE_PHA && PHA_TRIGGER_B && !pha_req_sent && !updating && !PHA_PENDING) ->
        /* Abstract server-side post-handshake CertificateRequest. */
        B2A_SEND(PHAReq, send_key, 0);
        pha_pending = true;
        pha_req_sent = true
    :: (ENABLE_EA && EA_TRIGGER_A && !ea_req_sent_a) ->
        /* Application-triggered Exported Authenticator request (A->B). */
        A2B_SEND(EAReq, send_key, 0);
        ea_pending = true;
        ea_req_sent_a = true

    :: (app_quota > 0) ->
        A2B_SEND(APP, send_key, 0);
        app_quota--

    :: A_RECV(APP, g, kx) ->
        assert(g == receive_key)
    :: A_RECV(KeyUpdate, g, kx) ->
        unexpected = true; break
    :: A_RECV(UnknownEKU, g, kx) ->
        unexpected = true; break
    :: A_RECV(EarlyEKU, g, kx) ->
        unexpected = true; break
    :: A_RECV(BadGroupReq, g, kx) ->
        illegal_parameter = true; break
    :: A_RECV(BadGroupResp, g, kx) ->
        illegal_parameter = true; break

    :: A_RECV(PHAReq, g, kx) ->
        assert(g == receive_key);
        /* Defer EKU while PHA is outstanding. */
        A2B_SEND(PHAFin, send_key, 0)
    :: A_RECV(EAReq, g, kx) ->
        assert(g == receive_key);
        /* Respond with abstract Exported Authenticator. */
        A2B_SEND(EAFin, send_key, 0)
    :: A_RECV(EAFin, g, kx) ->
        assert(g == receive_key);
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
        assert(g == receive_key); /* EKU messages under old keys */
        if
        :: PHA_PENDING ->
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
        :: PHA_PENDING -> skip
        :: (!updating || !initiated) -> skip
        :: (g != receive_key) -> skip
        :: else ->
            /* Step 4: update RECEIVE keys, then send Fin under OLD send keys. */
            receive_key = receive_key + 1;
            A2B_SEND(Fin, send_key, 0);
            /* Step 5: update SEND keys after sending Fin. */
            send_key = send_key + 1;
            updating = false;
            initiated = false;
            final_send_a = send_key;
            final_receive_a = receive_key;
            done_a = true;
            break
        fi

    :: A_RECV(Fin, g, kx) ->
        if
        :: PHA_PENDING -> skip
        :: (!updating || initiated) -> skip
        :: (g != receive_key) -> unexpected = true; break
        :: else ->
            /* Step 6: responder updates RECEIVE keys on Fin. */
            receive_key = receive_key + 1;
            updating = false;
            final_send_a = send_key;
            final_receive_a = receive_key;
            done_a = true;
            break
        fi
    od;

    /* Success states: keys are synchronized (both advanced by 1). */
    if
    :: (!unexpected && !illegal_parameter && done_a) -> assert(send_key == E+1 && receive_key == E+1)
    :: else -> skip
    fi
}

proctype PeerB() priority 1
{
    byte send_key = E;
    byte receive_key = E;
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
    :: (!PHA_PENDING && deferred_req_b) ->
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

    :: (ENABLE_EA && EA_TRIGGER_B && !ea_req_sent_b) ->
        /* Application-triggered Exported Authenticator request (B->A). */
        B2A_SEND(EAReq, send_key, 0);
        ea_pending = true;
        ea_req_sent_b = true
    :: (ENABLE_EA && EA_SPONT_TRIGGER_B && !ea_spont_sent_b) ->
        /* Spontaneous server authentication without prior request. */
        B2A_SEND(EAFin, send_key, 0);
        ea_spont_pending = true;
        ea_spont_sent_b = true

    :: (app_quota > 0) ->
        B2A_SEND(APP, send_key, 0);
        app_quota--

    :: B_RECV(APP, g, kx) ->
        assert(g == receive_key)
    :: B_RECV(KeyUpdate, g, kx) ->
        unexpected = true; break
    :: B_RECV(UnknownEKU, g, kx) ->
        unexpected = true; break
    :: B_RECV(EarlyEKU, g, kx) ->
        unexpected = true; break
    :: B_RECV(BadGroupReq, g, kx) ->
        illegal_parameter = true; break
    :: B_RECV(BadGroupResp, g, kx) ->
        illegal_parameter = true; break

    :: B_RECV(PHAFin, g, kx) ->
        assert(g == receive_key);
        if
        :: pha_pending ->
            pha_pending = false;
            pha_done = true
        :: else -> skip
        fi
    :: B_RECV(EAReq, g, kx) ->
        assert(g == receive_key);
        B2A_SEND(EAFin, send_key, 0)
    :: B_RECV(EAFin, g, kx) ->
        assert(g == receive_key);
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
        assert(g == receive_key);
        if
        :: PHA_PENDING ->
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
        :: PHA_PENDING -> skip
        :: (!updating || !initiated) -> skip
        :: (g != receive_key) -> skip
        :: else ->
            receive_key = receive_key + 1;
            B2A_SEND(Fin, send_key, 0);
            send_key = send_key + 1;
            updating = false;
            initiated = false;
            final_send_b = send_key;
            final_receive_b = receive_key;
            done_b = true;
            break
        fi

    :: B_RECV(Fin, g, kx) ->
        if
        :: PHA_PENDING -> skip
        :: (!updating || initiated) -> skip
        :: (g != receive_key) -> unexpected = true; break
        :: else ->
            receive_key = receive_key + 1;
            updating = false;
            final_send_b = send_key;
            final_receive_b = receive_key;
            done_b = true;
            break
        fi
    od;

    if
    :: (!unexpected && !illegal_parameter && done_b) -> assert(send_key == E+1 && receive_key == E+1)
    :: else -> skip
    fi
}

proctype ErrorInjector()
{
    if
    :: (INJECT_ERRORS) ->
        if
        :: A2B_SEND(KeyUpdate, E, 0)
        :: B2A_SEND(KeyUpdate, E, 0)
        :: A2B_SEND(UnknownEKU, E, 0)
        :: B2A_SEND(UnknownEKU, E, 0)
        :: A2B_SEND(EarlyEKU, E, 0)
        :: B2A_SEND(EarlyEKU, E, 0)
        :: A2B_SEND(BadGroupReq, E, 0)
        :: B2A_SEND(BadGroupReq, E, 0)
        :: A2B_SEND(BadGroupResp, E, 0)
        :: B2A_SEND(BadGroupResp, E, 0)
        fi
    :: else -> skip
    fi
}

init {
    atomic {
        run PeerA();
        run PeerB();
        run ErrorInjector();
    }
}

ltl no_unexpected { [](!unexpected) }
ltl no_illegal_parameter { [](!illegal_parameter) }
ltl key_sync {
    [](
        (!unexpected && !illegal_parameter && done_a && done_b) ->
        (final_send_a == final_receive_a &&
         final_send_b == final_receive_b &&
         final_send_a == final_send_b)
    )
}
