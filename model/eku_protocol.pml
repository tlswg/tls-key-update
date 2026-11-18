/*
 * Shared bounded EKU model. Entry points select DTLS or ordered TLS transport.
 * Each Peer reads its own protocol state. Cross-peer reads are confined to
 * network demultiplexing, termination detection, and verification properties.
 * Record handles name distinct (epoch, record-number) pairs. Retransmissions
 * allocate new handles but keep their handshake sequence, epoch and payload.
 *
 * DTLS completion at the initiator follows Step 7 of the DTLS procedure: any
 * record deprotected under the new receive epoch completes the exchange
 * before that record is processed. The explicit ACK of Fin is only the usual
 * such record. Consequently no new-epoch record is buffered or left
 * unacknowledged because of EKU.
 */
#ifndef TRANSPORT_TLS
#define TRANSPORT_TLS 0
#endif
#ifndef INITIATE_A
#define INITIATE_A 1
#endif
#ifndef INITIATE_B
#define INITIATE_B 1
#endif
#ifndef E
#define E 0
#endif
#ifndef INITIAL_A
#define INITIAL_A E
#endif
#ifndef INITIAL_B
#define INITIAL_B E
#endif
#ifndef KX_A
#define KX_A 10
#endif
#ifndef KX_B
#define KX_B 20
#endif
#ifndef DROPS
#define DROPS 1
#endif
#ifndef REQ_RETRIES
#define REQ_RETRIES 2
#endif
#ifndef FIN_RETRIES
#define FIN_RETRIES 2
#endif
#ifndef RESP_RETRIES
#define RESP_RETRIES 2
#endif
#ifndef HS_RETRIES
#define HS_RETRIES 2
#endif
#ifndef ENABLE_PHA
#define ENABLE_PHA 0
#endif
/* 0: permit before or after; 1: force server PHA before handling EKU; 2: after. */
#ifndef PHA_TIMING
#define PHA_TIMING 0
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
#ifndef EA_DELAY_UNTIL_EKU
#define EA_DELAY_UNTIL_EKU 0
#endif
#ifndef EXPIRE_OLD_EXPORTER
#define EXPIRE_OLD_EXPORTER 0
#endif
#ifndef ENABLE_CID
#define ENABLE_CID 0
#endif
/* 0: permit before or after; 1: force server CID before handling EKU; 2: after. */
#ifndef CID_TIMING
#define CID_TIMING 2
#endif
#ifndef CID_IMMEDIATE
#define CID_IMMEDIATE 1
#endif
#ifndef ENABLE_CID_REQUEST
#define ENABLE_CID_REQUEST 0
#endif
#ifndef PHA_TRIGGER_B
#define PHA_TRIGGER_B 1
#endif
#ifndef APP_QUOTA_A
#define APP_QUOTA_A APP_QUOTA
#endif
#ifndef APP_QUOTA_B
#define APP_QUOTA_B APP_QUOTA
#endif
#ifndef ENABLE_PRIOR_HS
#define ENABLE_PRIOR_HS 0
#endif
#ifndef ENABLE_TICKET
#define ENABLE_TICKET 0
#endif
#ifndef DEFER_RESP
#define DEFER_RESP 0
#endif
#ifndef EXTRA_REQUEST_ACK
#define EXTRA_REQUEST_ACK 0
#endif
#ifndef DROP_FIRST_FIN_ACK
#define DROP_FIRST_FIN_ACK 0
#endif
#ifndef APP_QUOTA
#define APP_QUOTA 0
#endif
#ifndef INJECT_ERRORS
#define INJECT_ERRORS 0
#endif
/* Mutations used only to show that regression properties detect old bugs. */
#ifndef FAULT_OLD_EPOCH_COMPLETES
#define FAULT_OLD_EPOCH_COMPLETES 0
#endif
#ifndef FAULT_GLOBAL_PHA
#define FAULT_GLOBAL_PHA 0
#endif
#ifndef FAULT_EA_CURRENT
#define FAULT_EA_CURRENT 0
#endif
#ifndef FAULT_EARLY_PHA
#define FAULT_EARLY_PHA 0
#endif
#ifndef ROUND_TIMEOUTS
#define ROUND_TIMEOUTS 0
#endif
#ifndef FAULT_PHA_TRANSCRIPT
#define FAULT_PHA_TRANSCRIPT 0
#endif
#ifndef FRAGMENT_PHA
#define FRAGMENT_PHA 0
#endif
#ifndef FAULT_CID_RETENTION
#define FAULT_CID_RETENTION 0
#endif

#define RECORDS 32
#define KINDS 20
#define IDLE 0
#define WAIT_RESPONSE 1
#define NEED_RESPONSE 2
#define WAIT_FINISH 3
#define NEED_FINISH 4
#define WAIT_ACK 5
#define COMPLETE 6
#define NO_RECORD 255

mtype = { Req, Resp, Fin, ACK, APP, PHAReq, PHAFin, EAReq, EAFin,
          NewCID, RequestCID, OtherHS, Ticket, BadMessage, BadGroup };

typedef Frame {
    mtype kind;
    byte epoch;
    byte hs_seq;
    byte record;
    byte cid;
    byte payload;       /* key share, selected authentication generation, or CID */
    byte context;       /* PHA transcript generation, separately from MAC generation */
    byte fragment;      /* 0: whole message; 1/2: two abstract PHA fragments */
    byte ack_epoch;
    byte ack_record;
};

typedef EndpointState {
    byte tx;
    byte rx;
    byte old_rx;
    bool retain_old;
    byte generation;
    byte phase;
    bool initiated;
    bool done;
    bool aborted;
    byte peer_share;
    byte next_send_seq;
    byte next_receive_seq;
    byte reassembly_mask;
    byte next_record;
    byte send_cid;
    bool issued_cid;
    bool cid_sent;
    bool cid_received;
    bool cid_request_sent;
    bool cid_request_received;
    bool prior_sent;
    bool ticket_sent;
    bool extra_ack_sent;
    bool error_sent;
    byte request_record;
    byte request_epoch;
    bool pha_sent;
    bool pha_waiting;   /* server-local outstanding authentication */
    bool pha_buffered;  /* client-local deferred operation */
    bool pha_done;
    byte pha_generation;
    byte pha_transcript;
    bool ea_requested;
    bool ea_pending;
    bool ea_reply_pending;
    bool ea_spont_sent;
    bool ea_done;
    bool ea_failed;
    byte ea_selected;
    byte ea_reply_generation;
    byte ea_reply_id;
    bool ea_spont_verified;
    bool ea_buffered;
    byte ea_buffered_generation;
    byte ea_buffered_id;
    bool old_exporter_available;
    byte app_left;
    bool started[KINDS];
    bool outstanding[KINDS];
    byte saved_epoch[KINDS];
    byte saved_seq[KINDS];
    byte saved_payload[KINDS];
    byte retries[KINDS];
    mtype record_kind[RECORDS];
    byte record_epoch[RECORDS];
    byte record_fragment[RECORDS];
    byte acknowledged_fragments[KINDS];
};

EndpointState peer[2];
chan path0[2] = [1] of { Frame };
chan path1[2] = [1] of { Frame };
chan inbox[2] = [2] of { Frame };
/* A separate reliable, authenticated application transport for EA objects.
   Its reliability is an explicit profile assumption, not a DTLS guarantee. */
chan application[2] = [2] of { mtype, byte, byte };
byte drops_left = DROPS;
bool finish_ack_lost;
/* Observers for Step 7: the kind of the new-epoch record that completed the
   exchange at the initiator, and whether it was an ACK naming a record other
   than Fin. Only one endpoint completes as initiator in this model. */
mtype completed_by;
bool completed_by_other_ack;
bool cid_changed_during_eku;
bool old_generation_ea_verified;
bool fin_retransmitted_new_cid;
bool retry_due[2];
bool pha_context_ok = true;
bool ea_context_ok = true;
bool unexpected;
bool illegal_parameter;

#define EMPTY_NETWORK (len(path0[0]) == 0 && len(path0[1]) == 0 && len(path1[0]) == 0 && len(path1[1]) == 0 && len(inbox[0]) == 0 && len(inbox[1]) == 0)
#define EMPTY_APPLICATION (len(application[0]) == 0 && len(application[1]) == 0)
#define AUTH_FINISHED (!ENABLE_PHA || !PHA_TRIGGER_B || (peer[0].pha_done && peer[1].pha_done))
#define EA_FINISHED (!ENABLE_EA || ((!EA_TRIGGER_A || peer[0].ea_requested && (peer[0].ea_done || peer[0].ea_failed)) && (!EA_TRIGGER_B || peer[1].ea_requested && (peer[1].ea_done || peer[1].ea_failed)) && (!EA_SPONT_TRIGGER_B || peer[1].ea_spont_sent && (peer[0].ea_spont_verified || peer[0].ea_failed)) && !peer[0].ea_reply_pending && !peer[1].ea_reply_pending && !peer[0].ea_buffered && !peer[1].ea_buffered))
#define CID_FINISHED (!ENABLE_CID || peer[0].cid_received)
#define OUTSTANDING(p) (peer[p].outstanding[Req] || peer[p].outstanding[Resp] || peer[p].outstanding[Fin] || peer[p].outstanding[PHAReq] || peer[p].outstanding[PHAFin] || peer[p].outstanding[NewCID] || peer[p].outstanding[RequestCID] || peer[p].outstanding[OtherHS] || peer[p].outstanding[Ticket])
#define RELIABILITY_FINISHED (!OUTSTANDING(0) && !OUTSTANDING(1))
#define ALL_FINISHED (peer[0].done && peer[1].done && AUTH_FINISHED && EA_FINISHED && CID_FINISHED && RELIABILITY_FINISHED && (!ENABLE_TICKET || peer[1].ticket_sent) && peer[0].app_left == 0 && peer[1].app_left == 0)
#define ACCEPT_EPOCH (incoming.epoch == peer[id].rx || (peer[id].retain_old && incoming.epoch == peer[id].old_rx))
#define ACKS_SENT_FIN (incoming.kind == ACK && incoming.ack_record < peer[id].next_record && peer[id].record_epoch[incoming.ack_record] == incoming.ack_epoch && peer[id].record_kind[incoming.ack_record] == Fin)
#define CAN_SEND ((TRANSPORT_TLS && nfull(inbox[other])) || (!TRANSPORT_TLS && (nfull(path0[id]) || nfull(path1[id]))))

inline emit(msg_kind, msg_epoch, msg_seq, msg_payload, acked_epoch, acked_record) {
    assert(peer[id].next_record < RECORDS);
    outgoing.kind = msg_kind;
    outgoing.epoch = msg_epoch;
    outgoing.hs_seq = msg_seq;
    outgoing.record = peer[id].next_record;
    outgoing.cid = peer[id].send_cid;
    outgoing.payload = msg_payload;
    outgoing.context = 0;
    outgoing.fragment = outgoing_fragment;
    if
    :: msg_kind == PHAReq || msg_kind == PHAFin -> outgoing.context = msg_payload
    :: else -> skip
    fi;
    if
    :: FAULT_PHA_TRANSCRIPT && msg_kind == PHAFin -> outgoing.context++
    :: else -> skip
    fi;
    outgoing.ack_epoch = acked_epoch;
    outgoing.ack_record = acked_record;
    peer[id].record_kind[peer[id].next_record] = msg_kind;
    peer[id].record_epoch[peer[id].next_record] = msg_epoch;
    peer[id].record_fragment[peer[id].next_record] = outgoing_fragment;
    peer[id].next_record++;
    if
    :: TRANSPORT_TLS -> inbox[other]!outgoing
    :: !TRANSPORT_TLS ->
        if
        :: path0[id]!outgoing
        :: path1[id]!outgoing
        fi
    fi
}

inline transmit_handshake(msg_kind, msg_epoch, msg_seq, msg_payload) {
    if
    :: !TRANSPORT_TLS && FRAGMENT_PHA && msg_kind == PHAReq ->
        outgoing_fragment = 1;
        emit(msg_kind, msg_epoch, msg_seq, msg_payload, 0, NO_RECORD);
        outgoing_fragment = 2;
        emit(msg_kind, msg_epoch, msg_seq, msg_payload, 0, NO_RECORD);
        outgoing_fragment = 0
    :: else -> emit(msg_kind, msg_epoch, msg_seq, msg_payload, 0, NO_RECORD)
    fi
}

inline send_handshake(msg_kind, msg_payload) {
    assert(!peer[id].started[msg_kind]);
    peer[id].started[msg_kind] = true;
    peer[id].saved_epoch[msg_kind] = peer[id].tx;
    peer[id].saved_seq[msg_kind] = peer[id].next_send_seq;
    peer[id].saved_payload[msg_kind] = msg_payload;
    peer[id].next_send_seq++;
    if
    :: !TRANSPORT_TLS -> peer[id].outstanding[msg_kind] = true
    :: else -> skip
    fi;
    if
    :: msg_kind == Req -> peer[id].retries[msg_kind] = REQ_RETRIES
    :: msg_kind == Resp -> peer[id].retries[msg_kind] = RESP_RETRIES
    :: msg_kind == Fin -> peer[id].retries[msg_kind] = FIN_RETRIES
    :: else -> peer[id].retries[msg_kind] = HS_RETRIES
    fi;
    transmit_handshake(msg_kind, peer[id].tx, peer[id].saved_seq[msg_kind], msg_payload)
}

inline acknowledge_incoming() {
    if
    :: TRANSPORT_TLS -> skip
    :: !TRANSPORT_TLS ->
        /* Step 7 activates the new sending epoch before a new-epoch record
           is processed, so an ACK never has to wait for the sending epoch.
           The assertion checks that claim; only the FAULT_EARLY_PHA variant,
           which skips Step 7, can reach the other branch. */
        assert(incoming.epoch <= peer[id].tx || FAULT_EARLY_PHA);
        if
        :: incoming.epoch <= peer[id].tx ->
            emit(ACK, peer[id].tx, 0, incoming.kind, incoming.epoch, incoming.record)
        :: else -> skip
        fi
    fi
}

inline validate_ea(selected_generation, operation_id) {
    if
    :: selected_generation > peer[id].generation ->
        peer[id].ea_buffered = true;
        peer[id].ea_buffered_generation = selected_generation;
        peer[id].ea_buffered_id = operation_id
    :: selected_generation < peer[id].generation && !peer[id].old_exporter_available ->
        peer[id].ea_failed = true;
        peer[id].ea_pending = false
    :: else ->
        if
        :: FAULT_EA_CURRENT -> checked_generation = peer[id].generation
        :: else -> checked_generation = selected_generation
        fi;
        ea_context_ok = ea_context_ok && checked_generation == selected_generation;
        assert(ea_context_ok);
        if
        :: selected_generation < peer[id].generation -> old_generation_ea_verified = true
        :: else -> skip
        fi;
        if
        :: operation_id == 3 -> peer[id].ea_spont_verified = true
        :: else -> peer[id].ea_done = true; peer[id].ea_pending = false
        fi
    fi
}

inline complete_initiator() {
    peer[id].tx = peer[id].rx;
    peer[id].generation++;
    peer[id].phase = COMPLETE;
    peer[id].done = true;
    peer[id].retain_old = false;
    if
    :: EXPIRE_OLD_EXPORTER -> peer[id].old_exporter_available = false
    :: else -> skip
    fi
}

/* DTLS Step 7. Runs for every successfully deprotected record, before the
   record is processed according to its content type. FAULT_EARLY_PHA skips
   it for a CertificateRequest, so that the request is answered under the
   pre-update context. FAULT_OLD_EPOCH_COMPLETES lets a pre-update record
   complete the exchange. */
inline complete_on_new_epoch_record() {
    if
    :: !TRANSPORT_TLS && peer[id].phase == WAIT_ACK &&
       (incoming.epoch == peer[id].rx || FAULT_OLD_EPOCH_COMPLETES) &&
       !(FAULT_EARLY_PHA && incoming.kind == PHAReq) ->
        completed_by = incoming.kind;
        if
        :: incoming.kind == ACK && !ACKS_SENT_FIN -> completed_by_other_ack = true
        :: else -> skip
        fi;
        peer[id].outstanding[Fin] = false;
        complete_initiator()
    :: else -> skip
    fi
}

inline handle_handshake() {
    if
    :: incoming.kind == Req ->
        peer[id].request_record = incoming.record;
        peer[id].request_epoch = incoming.epoch;
        if
        :: peer[id].phase == IDLE ->
            peer[id].peer_share = incoming.payload;
            peer[id].phase = NEED_RESPONSE
        :: peer[id].phase == WAIT_RESPONSE ->
            if
            :: incoming.payload > local_share ->
                /* Abandon the operation, not delivery of the earlier
                   handshake sequence number. A lost losing request must
                   still be retransmitted until acknowledged. */
                peer[id].initiated = false;
                peer[id].peer_share = incoming.payload;
                peer[id].phase = NEED_RESPONSE
            :: incoming.payload == local_share -> unexpected = true
            :: else -> acknowledge_incoming()
            fi
        :: else -> skip
        fi;
        if
        :: DEFER_RESP || peer[id].pha_waiting || peer[id].outstanding[OtherHS] -> acknowledge_incoming()
        :: else -> skip
        fi
    :: incoming.kind == Resp ->
        if
        :: peer[id].phase == WAIT_RESPONSE ->
            peer[id].outstanding[Req] = false;
            peer[id].old_rx = peer[id].rx;
            peer[id].retain_old = !TRANSPORT_TLS;
            peer[id].rx++;
            peer[id].phase = NEED_FINISH
        :: else -> skip
        fi
    :: incoming.kind == Fin ->
        if
        :: peer[id].phase == WAIT_FINISH ->
            assert(!peer[id].pha_waiting);
            peer[id].outstanding[Resp] = false;
            peer[id].outstanding[Req] = false; /* crossed losing request precedes Resp */
            peer[id].old_rx = peer[id].rx;
            peer[id].retain_old = !TRANSPORT_TLS;
            peer[id].rx++;
            if
            :: !TRANSPORT_TLS -> peer[id].tx++
            :: else -> skip
            fi;
            peer[id].generation++;
            peer[id].phase = COMPLETE;
            peer[id].done = true;
            if
            :: EXPIRE_OLD_EXPORTER -> peer[id].old_exporter_available = false
            :: else -> skip
            fi;
            acknowledge_incoming()
        :: else -> skip
        fi
    :: incoming.kind == PHAReq ->
        assert(id == 0);
        peer[id].pha_generation = incoming.payload;
        peer[id].pha_transcript = incoming.context;
        peer[id].pha_buffered = true
    :: incoming.kind == PHAFin ->
        assert(id == 1);
        pha_context_ok = pha_context_ok && incoming.payload == peer[id].pha_generation && incoming.context == peer[id].pha_transcript;
        assert(pha_context_ok);
        peer[id].outstanding[PHAReq] = false;
        peer[id].pha_waiting = false;
        peer[id].pha_done = true;
        acknowledge_incoming()
    :: incoming.kind == NewCID ->
        peer[id].cid_received = true;
        if
        :: CID_IMMEDIATE -> peer[id].send_cid = incoming.payload
        :: else -> skip
        fi;
        if
        :: peer[id].initiated && !peer[id].done -> cid_changed_during_eku = true
        :: else -> skip
        fi;
        acknowledge_incoming()
    :: incoming.kind == RequestCID ->
        peer[id].cid_request_received = true;
        acknowledge_incoming()
    :: incoming.kind == OtherHS || incoming.kind == Ticket ->
        /* Ticket contents have no resumption effect. RequestCID is ACKed,
           independently of any subsequent CID delivery. */
        acknowledge_incoming()
    fi
}

proctype Peer(byte id) {
    byte other = 1-id;
    byte local_share;
    byte scan;
    byte retry_kind;
    byte best_seq;
    byte ack_kind;
    byte checked_generation;
    byte outgoing_fragment;
    bool idle_transmissions;
    Frame incoming;
    Frame outgoing;
    mtype app_kind;
    byte app_generation;
    byte app_operation;
    if
    :: id == 0 -> local_share = KX_A
    :: else -> local_share = KX_B
    fi;
    if
    :: ENABLE_PHA && PHA_TRIGGER_B && PHA_TIMING == 1 && id == 1 ->
        atomic {
            peer[id].pha_sent = true;
            peer[id].pha_waiting = true;
            peer[id].pha_generation = peer[id].generation;
            peer[id].pha_transcript = peer[id].generation;
            send_handshake(PHAReq, peer[id].pha_generation)
        }
    :: else -> skip
    fi;
    if
    :: ENABLE_CID && !ENABLE_CID_REQUEST && CID_TIMING == 1 && id == 1 ->
        atomic {
            peer[id].cid_sent = true;
            peer[id].issued_cid = true;
            send_handshake(NewCID, 1)
        }
    :: else -> skip
    fi;

    do
    :: atomic {
        ALL_FINISHED && EMPTY_NETWORK && EMPTY_APPLICATION -> break
    }
    :: atomic {
        peer[id].aborted || unexpected || illegal_parameter -> break
    }
    :: atomic {
        ENABLE_PRIOR_HS && !peer[id].prior_sent && CAN_SEND &&
        (peer[id].phase == IDLE || peer[id].phase == NEED_RESPONSE) ->
        peer[id].prior_sent = true;
        send_handshake(OtherHS, 0)
    }
    :: atomic {
        ENABLE_CID_REQUEST && id == 0 && !peer[id].cid_request_sent && peer[id].phase == IDLE && CAN_SEND ->
        peer[id].cid_request_sent = true;
        send_handshake(RequestCID, 1)
    }
    :: atomic {
        peer[id].phase == IDLE && (id == 0 && INITIATE_A || id == 1 && INITIATE_B) &&
        (!ENABLE_PRIOR_HS || peer[id].prior_sent) && !peer[id].outstanding[OtherHS] &&
        (!ENABLE_CID_REQUEST || id != 0 || peer[id].cid_request_sent) &&
        !peer[id].outstanding[RequestCID] && !peer[id].outstanding[NewCID] &&
        !peer[id].pha_waiting && !peer[id].pha_buffered && !peer[id].outstanding[PHAFin] && CAN_SEND ->
        peer[id].initiated = true;
        peer[id].phase = WAIT_RESPONSE;
        send_handshake(Req, local_share)
    }
    :: atomic {
        peer[id].phase == NEED_RESPONSE && !peer[id].outstanding[OtherHS] &&
        !peer[id].outstanding[RequestCID] && !peer[id].outstanding[NewCID] &&
        (!ENABLE_PRIOR_HS || peer[id].prior_sent) &&
        !peer[id].pha_waiting && !peer[id].pha_buffered && !peer[id].outstanding[PHAFin] && CAN_SEND ->
        send_handshake(Resp, local_share);
        if
        :: TRANSPORT_TLS -> peer[id].tx++
        :: else -> skip
        fi;
        peer[id].phase = WAIT_FINISH
    }
    :: atomic {
        peer[id].phase == NEED_FINISH && !peer[id].pha_buffered && !peer[id].outstanding[PHAFin] && CAN_SEND ->
        send_handshake(Fin, 0);
        if
        :: TRANSPORT_TLS -> complete_initiator()
        :: else -> peer[id].phase = WAIT_ACK
        fi
    }
    :: atomic {
        ENABLE_PHA && PHA_TRIGGER_B && id == 1 && !peer[id].pha_sent && CAN_SEND &&
        (peer[id].phase == IDLE && PHA_TIMING != 2 || peer[id].done && PHA_TIMING != 1) ->
        peer[id].pha_sent = true;
        peer[id].pha_waiting = true;
        peer[id].pha_generation = peer[id].generation;
        peer[id].pha_transcript = peer[id].generation;
        send_handshake(PHAReq, peer[id].pha_generation)
    }
    :: atomic {
        /* With Step 7 a request is never pending in WAIT_ACK: a new-epoch
           request completes the exchange first, and an earlier one is
           answered before Fin is sent. Only FAULT_EARLY_PHA gets there. */
        peer[id].pha_buffered && CAN_SEND && (peer[id].phase != WAIT_ACK || FAULT_EARLY_PHA) ->
        peer[id].pha_buffered = false;
        pha_context_ok = pha_context_ok && peer[id].generation == peer[id].pha_generation && peer[id].generation == peer[id].pha_transcript;
        assert(pha_context_ok);
        send_handshake(PHAFin, peer[id].pha_generation);
        if
        :: TRANSPORT_TLS -> peer[id].pha_done = true
        :: else -> skip
        fi
    }
    :: atomic {
        ENABLE_CID && id == 1 && !peer[id].cid_sent && CAN_SEND &&
        (!ENABLE_CID_REQUEST || peer[id].cid_request_received) &&
        (peer[id].phase == IDLE && CID_TIMING != 2 || peer[id].done && CID_TIMING != 1) ->
        peer[id].cid_sent = true;
        peer[id].issued_cid = true;
        send_handshake(NewCID, 1)
    }
    :: atomic {
        ENABLE_TICKET && id == 1 && peer[id].done && !peer[id].ticket_sent && CAN_SEND ->
        peer[id].ticket_sent = true;
        send_handshake(Ticket, 0)
    }
    :: atomic {
        ENABLE_EA && (id == 0 && EA_TRIGGER_A || id == 1 && EA_TRIGGER_B) && !peer[id].ea_requested && nfull(application[other]) ->
        peer[id].ea_requested = true;
        peer[id].ea_pending = true;
        peer[id].ea_selected = peer[id].generation;
        application[other]!EAReq,peer[id].ea_selected,id+1
    }
    :: atomic {
        peer[id].ea_reply_pending && nfull(application[other]) && (!EA_DELAY_UNTIL_EKU || peer[id].done) ->
        peer[id].ea_reply_pending = false;
        application[other]!EAFin,peer[id].ea_reply_generation,peer[id].ea_reply_id
    }
    :: atomic {
        ENABLE_EA && EA_SPONT_TRIGGER_B && id == 1 && !peer[id].ea_spont_sent && peer[id].done && nfull(application[other]) ->
        peer[id].ea_spont_sent = true;
        application[other]!EAFin,peer[id].generation,3
    }
    :: atomic {
        peer[id].ea_buffered && peer[id].ea_buffered_generation <= peer[id].generation ->
        peer[id].ea_buffered = false;
        validate_ea(peer[id].ea_buffered_generation, peer[id].ea_buffered_id)
    }
    :: atomic {
        peer[id].app_left > 0 && CAN_SEND ->
        peer[id].app_left--;
        emit(APP, peer[id].tx, 0, 0, 0, NO_RECORD)
    }
    :: atomic {
        !TRANSPORT_TLS && EXTRA_REQUEST_ACK && peer[id].done && !peer[id].initiated && !peer[id].extra_ack_sent && CAN_SEND ->
        peer[id].extra_ack_sent = true;
        emit(ACK, peer[id].tx, 0, Req, peer[id].request_epoch, peer[id].request_record)
    }
    :: atomic {
        !TRANSPORT_TLS && EMPTY_NETWORK && !peer[id].aborted && OUTSTANDING(id) &&
        (!ROUND_TIMEOUTS || retry_due[id]) &&
        (!FAULT_GLOBAL_PHA || !peer[1].pha_waiting) ->
        retry_due[id] = false;
        scan = 1; retry_kind = 0; best_seq = 255;
        do
        :: scan < KINDS ->
            if
            :: peer[id].outstanding[scan] && peer[id].saved_seq[scan] < best_seq ->
                retry_kind = scan; best_seq = peer[id].saved_seq[scan]
            :: else -> skip
            fi;
            scan++
        :: else -> break
        od;
        assert(retry_kind > 0 && retry_kind < KINDS);
        if
        :: peer[id].retries[retry_kind] > 0 ->
            peer[id].retries[retry_kind]--;
            if
            :: retry_kind == Fin && peer[id].send_cid == 1 && peer[id].phase == WAIT_ACK -> fin_retransmitted_new_cid = true
            :: else -> skip
            fi;
            transmit_handshake(retry_kind, peer[id].saved_epoch[retry_kind], peer[id].saved_seq[retry_kind], peer[id].saved_payload[retry_kind])
        :: else -> peer[id].aborted = true
        fi
    }
    :: atomic {
        ROUND_TIMEOUTS && retry_due[id] && !OUTSTANDING(id) -> retry_due[id] = false
    }
    :: atomic {
        INJECT_ERRORS && id == 0 && !peer[id].error_sent && CAN_SEND ->
        peer[id].error_sent = true;
        if
        :: INJECT_ERRORS == 1 -> emit(BadMessage, peer[id].tx, 0, 0, 0, NO_RECORD)
        :: INJECT_ERRORS == 2 -> emit(ACK, peer[id].tx, 0, 0, peer[id].tx+1, 0)
        :: INJECT_ERRORS == 3 -> emit(BadGroup, peer[id].tx, 0, 0, 0, NO_RECORD)
        fi
    }
    :: atomic {
        application[id]?app_kind,app_generation,app_operation;
        if
        :: app_kind == EAReq ->
            /* Capture the selected derived context before delaying delivery. */
            peer[id].ea_reply_pending = true;
            peer[id].ea_reply_generation = app_generation;
            peer[id].ea_reply_id = app_operation
        :: app_kind == EAFin ->
            if
            :: app_operation == id+1 -> assert(app_generation == peer[id].ea_selected)
            :: else -> assert(id == 0 && app_operation == 3)
            fi;
            validate_ea(app_generation, app_operation)
        fi
    }
    :: atomic {
        inbox[id]?incoming;
        /* CID demultiplexing precedes key selection. Both issued CIDs remain
           routable in this bounded model; no CID-retirement protocol is assumed. */
        assert(incoming.cid == 0 || peer[id].issued_cid);
        if
        :: FAULT_CID_RETENTION && incoming.cid == 1 -> peer[id].retain_old = false
        :: else -> skip
        fi;
        if
        :: !ACCEPT_EPOCH ->
            assert(!TRANSPORT_TLS)
        :: else ->
            complete_on_new_epoch_record();
            if
            :: peer[id].retain_old && incoming.epoch == peer[id].rx -> peer[id].retain_old = false
            :: else -> skip
            fi;
            if
            :: incoming.kind == ACK ->
                assert(!TRANSPORT_TLS);
                if
                :: incoming.ack_epoch > incoming.epoch -> illegal_parameter = true
                :: incoming.ack_record < peer[id].next_record &&
                   peer[id].record_epoch[incoming.ack_record] == incoming.ack_epoch ->
                    ack_kind = peer[id].record_kind[incoming.ack_record];
                    if
                    :: peer[id].record_fragment[incoming.ack_record] == 0 ->
                        peer[id].outstanding[ack_kind] = false
                    :: else ->
                        peer[id].acknowledged_fragments[ack_kind] = peer[id].acknowledged_fragments[ack_kind] | peer[id].record_fragment[incoming.ack_record];
                        if
                        :: peer[id].acknowledged_fragments[ack_kind] == 3 -> peer[id].outstanding[ack_kind] = false
                        :: else -> skip
                        fi
                    fi;
                    if
                    :: ack_kind == PHAFin -> peer[id].pha_done = true
                    :: else -> skip
                    fi
                :: else -> skip
                fi
            :: incoming.kind == APP ->
                if
                :: incoming.epoch == peer[id].rx -> peer[id].retain_old = false
                :: else -> skip
                fi
            :: incoming.kind == BadMessage -> unexpected = true
            :: incoming.kind == BadGroup -> illegal_parameter = true
            :: else ->
                if
                :: incoming.hs_seq < peer[id].next_receive_seq -> acknowledge_incoming()
                :: incoming.hs_seq == peer[id].next_receive_seq ->
                    if
                    :: incoming.fragment == 0 ->
                        peer[id].next_receive_seq++;
                        handle_handshake()
                    :: else ->
                        assert(incoming.kind == PHAReq);
                        peer[id].reassembly_mask = peer[id].reassembly_mask | incoming.fragment;
                        acknowledge_incoming();
                        if
                        :: peer[id].reassembly_mask == 3 ->
                            peer[id].next_receive_seq++;
                            peer[id].reassembly_mask = 0;
                            handle_handshake()
                        :: else -> skip
                        fi
                    fi
                :: else -> skip /* out of order: not processed, not ACKed */
                fi
            fi
        fi
    }
    od
}

proctype Network() {
    Frame packet;
    byte destination;
    do
    :: atomic { ALL_FINISHED && EMPTY_NETWORK && EMPTY_APPLICATION -> break }
    :: atomic {
        peer[0].aborted && len(inbox[0]) > 0 -> inbox[0]?packet
    }
    :: atomic {
        peer[1].aborted && len(inbox[1]) > 0 -> inbox[1]?packet
    }
    :: atomic {
        ROUND_TIMEOUTS && timeout && EMPTY_NETWORK && !retry_due[0] && !retry_due[1] &&
        (OUTSTANDING(0) || OUTSTANDING(1)) ->
        retry_due[0] = OUTSTANDING(0);
        retry_due[1] = OUTSTANDING(1)
    }
    :: atomic {
        if
        :: len(path0[0]) > 0 && (nfull(inbox[1]) || peer[1].aborted) -> path0[0]?packet; destination = 1
        :: len(path1[0]) > 0 && (nfull(inbox[1]) || peer[1].aborted) -> path1[0]?packet; destination = 1
        :: len(path0[1]) > 0 && (nfull(inbox[0]) || peer[0].aborted) -> path0[1]?packet; destination = 0
        :: len(path1[1]) > 0 && (nfull(inbox[0]) || peer[0].aborted) -> path1[1]?packet; destination = 0
        fi;
        if
        :: peer[destination].aborted -> skip
        :: !peer[destination].aborted && packet.kind == ACK && packet.payload == Fin && drops_left > 0 &&
           DROP_FIRST_FIN_ACK && !finish_ack_lost ->
            drops_left--; finish_ack_lost = true
        :: !peer[destination].aborted && (!DROP_FIRST_FIN_ACK || finish_ack_lost) && drops_left > 0 -> drops_left--
        :: !peer[destination].aborted && !(DROP_FIRST_FIN_ACK && !finish_ack_lost && drops_left > 0 && packet.kind == ACK && packet.payload == Fin) ->
            inbox[destination]!packet
        fi
    }
    od
}

init {
    atomic {
        assert(INITIAL_A == INITIAL_B);
        peer[0].tx = INITIAL_A; peer[0].rx = INITIAL_A;
        peer[1].tx = INITIAL_B; peer[1].rx = INITIAL_B;
        peer[0].old_exporter_available = true;
        peer[1].old_exporter_available = true;
        peer[0].app_left = APP_QUOTA_A; peer[1].app_left = APP_QUOTA_B;
        if
        :: !TRANSPORT_TLS -> run Network()
        :: else -> skip
        fi;
        run Peer(0);
        run Peer(1)
    }
}

ltl no_unexpected { [](!unexpected) }
ltl no_illegal_parameter { [](!illegal_parameter) }
/* Matching directional epochs once both endpoints have completed. This is
   also the key synchronization property: the former `key_sync` claim had
   the same formula and was removed. */
ltl epoch_consistency {
    []((peer[0].done && peer[1].done) ->
       (peer[0].tx == peer[1].rx && peer[1].tx == peer[0].rx))
}
/* DTLS Step 7: the initiator activates its new sending epoch only after the
   responder has processed Fin, and sends nothing under it before that. */
ltl new_epoch_confirms_finish {
    []((!TRANSPORT_TLS && peer[0].initiated && peer[0].done -> peer[1].done) &&
       (!TRANSPORT_TLS && peer[1].initiated && peer[1].done -> peer[0].done) &&
       ((!TRANSPORT_TLS && peer[0].phase == WAIT_ACK) -> peer[0].tx == INITIAL_A) &&
       ((!TRANSPORT_TLS && peer[1].phase == WAIT_ACK) -> peer[1].tx == INITIAL_B))
}
ltl authentication_context { [](pha_context_ok && ea_context_ok) }
ltl protocol_safety {
    [](!unexpected && !illegal_parameter && pha_context_ok && ea_context_ok &&
       ((!TRANSPORT_TLS && peer[0].initiated && peer[0].done) -> peer[1].done) &&
       ((!TRANSPORT_TLS && peer[1].initiated && peer[1].done) -> peer[0].done) &&
       ((!TRANSPORT_TLS && peer[0].phase == WAIT_ACK) -> peer[0].tx == INITIAL_A) &&
       ((!TRANSPORT_TLS && peer[1].phase == WAIT_ACK) -> peer[1].tx == INITIAL_B) &&
       ((peer[0].done && peer[1].done) -> (peer[0].tx == peer[1].rx && peer[1].tx == peer[0].rx)))
}
ltl successful_completion { <> ALL_FINISHED }
ltl no_deadlock {
    <> ((peer[0].done || peer[0].aborted || unexpected || illegal_parameter) &&
        (peer[1].done || peer[1].aborted || unexpected || illegal_parameter))
}
/* These negated reachability claims must FAIL in the dedicated witness profiles. */
ltl witness_pha_completes_eku { [] !(finish_ack_lost && completed_by == PHAReq && ALL_FINISHED) }
ltl witness_cid_completes_eku { [] !(finish_ack_lost && completed_by == NewCID && ALL_FINISHED) }
ltl witness_app_completes_eku { [] !(finish_ack_lost && completed_by == APP && ALL_FINISHED) }
ltl witness_other_ack_completes_eku { [] !(finish_ack_lost && completed_by_other_ack && ALL_FINISHED) }
ltl witness_cid_old_epoch { [] !(cid_changed_during_eku && fin_retransmitted_new_cid && ALL_FINISHED) }
ltl witness_old_ea { [] !(old_generation_ea_verified && ALL_FINISHED) }
ltl witness_expired_ea { [] !((peer[0].ea_failed || peer[1].ea_failed) && ALL_FINISHED) }
