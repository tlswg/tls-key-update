/* 
 * TLS 1.3 Extended Key Update (EKU) - SPIN Model
 *
 * State/variable conventions (aligned with DTLS model where sensible):
 *   - send_key, receive_key : generation counters of application_traffic_secret (current, new keying material, ...)
 *   - E        : initial key
 *   - updating : 1 while an EKU exchange is in progress
 *   - accepted : 1 after responder accepts a request
 *   - Messages: Req, Resp_* (accepted/retry/rejected/clashed), NKU
 *
 * TLS rules captured (reliable transport):
 *   1) Initiator: send Req; wait Resp.
 *   2) Responder: on Req, send Resp(accepted) or a rejection.
 *   3) If accepted, initiator sends NKU (under OLD keys) and immediately
 *      updates SEND keys (send_key := send_key+1).
 *   4) Responder on NKU-in: updates RECEIVE keys (receive_key := receive_key+1), sends NKU
 *      (under OLD keys), then updates SEND keys (send_key := send_key+1).
 *   5) Initiator on responder NKU-in: updates RECEIVE keys (receive_key := receive_key+1).
 *
 * After success, both peers have send_key==receive_key==E+1 and updating==0.
 */

#define E 3  /* initial application traffic secret generation */
#define G_I 1 /* initiator's chosen group id (arbitrary) */
#define G_R 1 /* responder's chosen group id (must be mutually supported) */

mtype = { Req, Resp_acc, Resp_retry, Resp_rej, Resp_clashed, NKU };

chan c_cli_to_srv = [0] of { mtype, byte }; /* reliable, in-order (rendezvous) */
chan c_srv_to_cli = [0] of { mtype, byte };

/* Shared monitors / assertions */
bool done_initiator = 0;
bool done_responder = 0;

/* ------------ Initiator (TLS 1.3) ------------ */
proctype Initiator()
{
    /* Variables aligned with DTLS model naming */
    byte send_key = E;      /* current send generation */
    byte receive_key = E;   /* current receive generation */
    bool updating = 0;
    bool accepted = 0;
    byte group = G_I;

START:
    /* Step 1: send ExtendedKeyUpdate(request) */
    updating = 1;
    c_cli_to_srv ! Req, group;

WAIT_RESP:
    do
    :: c_srv_to_cli ? Resp_acc, group ->
        /* Step 3: on accepted, derive new secrets (abstracted) */
        accepted = 1;

        /* Send NKU under OLD keys */
        c_cli_to_srv ! NKU, 0;

        /* Immediately update SEND keys (send_key := send_key+1) */
        send_key = send_key + 1;

        goto SENT_NKU_WAIT_R_NKU

    :: c_srv_to_cli ? Resp_retry, group ->
        /* Abort exchange for this model; no timers in TLS */
        updating = 0;
        accepted = 0;
        goto FINISHED

    :: c_srv_to_cli ? Resp_rej, group ->
        updating = 0;
        accepted = 0;
        goto FINISHED

    :: c_srv_to_cli ? Resp_clashed, group ->
        updating = 0;
        accepted = 0;
        goto FINISHED
    od;

SENT_NKU_WAIT_R_NKU:
    /* Step 5: receive responder NKU (still under OLD keys) */
    c_srv_to_cli ? NKU, 0;

    /* Update RECEIVE keys (receive_key := receive_key+1) */
    receive_key = receive_key + 1;

    updating = 0;

FINISHED:
    /* Success condition: if accepted, both gens should be E+1 */
    if
    :: (accepted) ->
        assert(send_key == E+1 && receive_key == E+1)
        ; assert(!updating)
    :: else ->
        assert(send_key == E && receive_key == E)
        ; assert(!updating)
    fi;

    done_initiator = 1;
    /* Keep process alive to allow SPIN to check properties */
    /* end of Initiator */
    assert(done_initiator) /* stable end-state marker */
}

/* ------------ Responder (TLS 1.3) ------------ */
proctype Responder()
{
    byte send_key = E;      /* current send generation */
    byte receive_key = E;   /* current receive generation */
    bool updating = 0;
    bool accepted = 0;
    byte group = G_R;

START:
    /* Step 2: wait for ExtendedKeyUpdate(request) */
    c_cli_to_srv ? Req, group;
    updating = 1;

    /* For the main path, accept */
    accepted = 1;
    c_srv_to_cli ! Resp_acc, group;

WAIT_I_NKU:
    /* Step 4: receive initiator NKU (old keys), update RECEIVE */
    c_cli_to_srv ? NKU, 0;
    receive_key = receive_key + 1; /* update receive generation */

    /* Send our NKU under OLD keys */
    c_srv_to_cli ! NKU, 0;

    /* Immediately update SEND keys (send_key := send_key+1) */
    send_key = send_key + 1;

    updating = 0;

FINISHED:
    if
    :: (accepted) -> assert(send_key == E+1 && receive_key == E+1)
    :: else -> skip
    fi;

    done_responder = 1;
    assert(done_responder) /* stable end-state marker */
}

/* ------------ System composition ------------ */
init {
    atomic {
        /* Start both peers */
        run Initiator();
        run Responder();
    }

    /* Global success condition: both peers finished and agree on gen E+1 */
    do
    :: (done_initiator && done_responder) ->
        /* No explicit shared state, but we can model-check safety properties */
        break
    od;
}
