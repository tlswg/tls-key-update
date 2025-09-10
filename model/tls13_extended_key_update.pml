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

#define E 3    /* initial application traffic secret generation */
#define G_I 1  /* initiator's chosen group id (arbitrary) */
#define G_R 1  /* responder's chosen group id (must be mutually supported) */

mtype = { Req, Resp_acc, Resp_retry, Resp_rej, Resp_clashed, NKU };

chan c_cli_to_srv = [0] of { mtype, byte }; /* rendezvous channel: client → server */
chan c_srv_to_cli = [0] of { mtype, byte }; /* rendezvous channel: server → client */

/* Global markers to detect when each peer has finished */
bool done_initiator = 0;
bool done_responder = 0;

/* ------------ Initiator (TLS 1.3) ------------ */
proctype Initiator()
{
    byte send_key = E;      /* send key, initially E */
    byte receive_key = E;   /* receive key, initially E */
    bool updating = 0;      /* true while an EKU exchange is ongoing */
    bool accepted = 0;      /* true if responder accepted EKU */
    byte group = G_I;       /* group identifier */

START:
    updating = 1;           /* mark that EKU exchange is starting */
    c_cli_to_srv ! Req, group; /* send EKU request to responder */

WAIT_RESP:
    do
    :: c_srv_to_cli ? Resp_acc, group ->  /* case: responder accepts */
        accepted = 1;                    /* record acceptance */
        c_cli_to_srv ! NKU, 0;           /* send NKU message under OLD keys */
        send_key = send_key + 1;         /* immediately advance own send_key */
        goto SENT_NKU_WAIT_R_NKU         

    :: c_srv_to_cli ? Resp_retry, group -> /* case: retry requested */
        updating = 0;                     /* abort the exchange */
        accepted = 0;                     /* mark as not accepted */
        goto FINISHED

    :: c_srv_to_cli ? Resp_rej, group ->   /* case: rejected outright */
        updating = 0;                     
        accepted = 0;
        goto FINISHED

    :: c_srv_to_cli ? Resp_clashed, group -> /* case: clash detected */
        updating = 0;
        accepted = 0;
        goto FINISHED
    od;

SENT_NKU_WAIT_R_NKU:
    c_srv_to_cli ? NKU, 0;              /* wait for responder’s NKU */
    receive_key = receive_key + 1;      /* update own receive_key */
    updating = 0;                       /* EKU exchange finished */

FINISHED:
    if
    :: (accepted) ->
        /* success path: both keys must have advanced */
        assert(send_key == E+1 && receive_key == E+1);
        assert(!updating); /* must not still be updating */
    :: else ->
        /* abort path: keys must remain unchanged */
        assert(send_key == E && receive_key == E);
        assert(!updating);
    fi;

    done_initiator = 1;                 /* mark initiator done */
    assert(done_initiator)              /* stable end-state marker */
}

/* ------------ Responder (TLS 1.3) ------------ */
proctype Responder()
{
    byte send_key = E;      /* send generation counter */
    byte receive_key = E;   /* receive generation counter */
    bool updating = 0;
    bool accepted = 0;
    byte group = G_R;

START:
    c_cli_to_srv ? Req, group;   /* wait for EKU request from initiator */
    updating = 1;                /* mark that update is in progress */
    accepted = 1;                /* in this model, always accept */
    c_srv_to_cli ! Resp_acc, group; /* send acceptance response */

WAIT_I_NKU:
    c_cli_to_srv ? NKU, 0;       /* receive initiator’s NKU */
    receive_key = receive_key + 1; /* advance own receive_key */

    c_srv_to_cli ! NKU, 0;       /* send NKU back under OLD keys */
    send_key = send_key + 1;     /* then advance own send_key */
    updating = 0;                /* update exchange finished */

FINISHED:
    if
    :: (accepted) ->
        /* success path: both counters must have advanced */
        assert(send_key == E+1 && receive_key == E+1);
        assert(!updating);
    :: else ->
        /* not expected in this model, but if rejection: no change */
        assert(send_key == E && receive_key == E);
        assert(!updating);
    fi;

    done_responder = 1;          /* mark responder done */
    assert(done_responder)       /* stable end-state marker */
}

/* ------------ System composition ------------ */
init {
    atomic {
        run Initiator(); /* start initiator process */
        run Responder(); /* start responder process */
    }

    do
    :: (done_initiator && done_responder) ->
        break; /* terminate when both peers are finished */
    od;
}
