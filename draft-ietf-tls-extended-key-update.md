---
title: Extended Key Update for Transport Layer Security (TLS) 1.3

abbrev: Extended Key Update for TLS
docname: draft-ietf-tls-extended-key-update-latest
category: std

ipr: trust200902
submissiontype: IETF
area: "Security"
workgroup: "Transport Layer Security"
keyword: Internet-Draft

stand_alone: yes
pi:
  rfcedstyle: yes
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  inline: yes
  text-list-symbols: -o*+
  docmapping: yes
author:
 -
      ins: H. Tschofenig
      name: Hannes Tschofenig
      email: hannes.tschofenig@gmx.net
      org: Siemens
 -
      ins: M. Tüxen
      name: Michael Tüxen
      email: tuexen@fh-muenster.de
      org: Münster Univ. of Applied Sciences
 -
      ins: T. Reddy
      name: Tirumaleswar Reddy
      email: kondtir@gmail.com
      org: Nokia
 -
      ins: S. Fries
      name: Steffen Fries
      email: steffen.fries@siemens.com
      org: Siemens
 -
      ins: "Y. Rosomakho"
      fullname: Yaroslav Rosomakho
      organization: Zscaler
      email: yrosomakho@zscaler.com

normative:
  RFC2119:
  I-D.ietf-tls-rfc8446bis:
  RFC9147:
  I-D.ietf-tls-tlsflags:
informative:
  I-D.ietf-tls-ecdhe-mlkem:
  I-D.ietf-tls-mlkem:
  RFC7624:
  I-D.ietf-tls-hybrid-design:
  I-D.ietf-tls-keylogfile:
  RFC5746:
  ANSSI:
     author:
        org: ANSSI
     title: Recommendations for securing networks with IPsec, Technical Report
     target: https://www.ssi.gouv.fr/uploads/2015/09/NT_IPsec_EN.pdf
     date: August 2015
  TLS-Ext-Registry:
     author:
        org: IANA
     title: Transport Layer Security (TLS) Extensions
     target: https://www.iana.org/assignments/tls-extensiontype-values
     date: November 2023
  CDM23:
     author:
        org: ACM
     title: "Keeping Up with the KEMs: Stronger Security Notions for KEMs and automated analysis of KEM-based protocols"
     target: https://eprint.iacr.org/2023/1933.pdf
     date: November 2023

--- abstract

TLS 1.3 ensures forward secrecy by performing an ephemeral Diffie-Hellman key exchange
during the initial handshake, protecting past communications even if a party's
long-term keys are later compromised. While the built-in KeyUpdate mechanism allows
traffic keys to be refreshed during a session, it does not introduce new forward-secret
key material. This limitation can pose a security risk in long-lived sessions, such as
those found in industrial IoT or telecommunications environments.

To address this, this specification defines an extended key update mechanism that
performs a fresh Diffie-Hellman exchange within an active session, thereby
re-establishing forward secrecy beyond the initial handshake. By forcing attackers
to exfiltrate new key material repeatedly, this approach mitigates the risks
associated with static key compromise. Regular renewal of session keys helps
contain the impact of such compromises. The extension is applicable to both TLS 1.3
and DTLS 1.3.

--- middle

#  Introduction

The Transport Layer Security (TLS) 1.3 protocol provides forward secrecy by using
an ephemeral Diffie-Hellman (DHE) key exchange during the initial handshake. This
ensures that encrypted communication remains confidential even if an attacker
later obtains a party's long-term private key, protecting against passive adversaries
who record encrypted traffic for later decryption.

TLS 1.3 also includes a KeyUpdate mechanism that allows traffic keys to be refreshed
during an established session. However, this mechanism does not introduce new
forward-secret key material, as it applies only a key derivation function to the
previous application traffic secret as input. While this design is generally sufficient
for short-lived connections, it may present security limitations in scenarios where
sessions persist for extended periods, such as in industrial IoT or telecommunications
systems, where continuous availability is critical and session renegotiation or resumption
is impractical.

Earlier versions of TLS supported session renegotiation, which allowed peers to negotiate
fresh keying material, including performing new Diffie-Hellman exchanges during the
session lifetime. Due to protocol complexity and known vulnerabilities, renegotiation
was first restricted by {{RFC5746}} and ultimately removed in TLS 1.3. While the
KeyUpdate message was introduced to offer limited rekeying functionality, it does
not fulfill the same cryptographic role as renegotiation and cannot refresh
long-term secrets or derive new secrets from fresh DHE input.

Security guidance from national agencies, such as ANSSI (France {{ANSSI}}), recommends the
periodic renewal of cryptographic keys during long-lived sessions to limit the
impact of key compromise. This approach encourages designs that force an
attacker to perform dynamic key exfiltration, as defined in {{RFC7624}}. Dynamic
key exfiltration refers to attack scenarios where an adversary must repeatedly
extract fresh keying material to maintain access to protected data, increasing
operational cost and risk for the attacker. In contrast, static key exfiltration,
where a long-term secret is extracted once and reused, poses a greater long-term
threat, especially when session keys are not refreshed with forward-secret input.

This specification defines a TLS extension that introduces an extended key update
mechanism. Unlike the standard key update, this mechanism allows peers to perform a
fresh Diffie-Hellman exchange within an active session using one of the groups
negotiated during the initial handshake. By periodically rerunning (EC)DHE, this
extension enables the derivation of new traffic secrets that are independent of
prior key material. As noted in Appendix F of {{I-D.ietf-tls-rfc8446bis}}, this
approach mitigates the risk of static key exfiltration and shifts the attacker
burden toward dynamic key exfiltration.

The proposed extension is applicable to both TLS 1.3 {{I-D.ietf-tls-rfc8446bis}} and DTLS 1.3  {{RFC9147}}. For clarity,
the term "TLS" is used throughout this document to refer to both protocols unless
otherwise specified.

# Terminology and Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119 {{RFC2119}}.

To distinguish the key update procedure defined in {{I-D.ietf-tls-rfc8446bis}}
from the key update procedure specified in this document, we use the terms
"standard key update" and "extended key update", respectively.

The following variables and abbreviations are used in the state machine diagrams.

- rx - current, accepted receive epoch.
- tx - current transmit epoch used for tagging outgoing messages.
- E - initial epoch value.
- updating - true while a key-update handshake is in progress.
- accepted - set to true after an accepted Resp; indicates the peer has
  agreed to proceed with the update and that new key material can be derived.
- old_rx - the previous receive epoch remembered during retention.
- retain_old - when true, receiver accepts tags old_rx and rx.
- tag=... - the TX-epoch value written on an outgoing message.
- e==... - the tag carried on an incoming message (what the peer sent).
- Protocol message types - ExtendedKeyUpdate(request) (Req) /
  ExtendedKeyUpdate(response) (Resp) / ExtendedKeyUpdate(new_key_update) (NKU) /
  ACK (from {{Section 7 of RFC9147}} / APP for application data.
- FINISHED / START/IDLE / WAIT_RESP / SENT_NKU / WAIT_R_NKU - diagram
  states; FINISHED denotes the steady state after success or reject.

# Negotiating the Extended Key Update

Client and servers use the TLS flags extension
{{I-D.ietf-tls-tlsflags}} to indicate support for the functionality
defined in this document.  We call this the "extended_key_update"
extension and the corresponding flag is called "Extended_Key_Update"
flag.

The "Extended_Key_Update" flag proposed by the client in the
ClientHello (CH) MUST be acknowledged in the EncryptedExtensions
(EE), if the server also supports the functionality defined in this
document and is configured to use it.

If the "Extended_Key_Update" flag is not set, servers ignore any of the
functionality specified in this document and applications that
require perfect forward security will have to initiate a full
handshake.

# Extended Key Update Messages {#ext-key-update}

If the client and server agree to use the extended key update mechanism,
the standard key update MUST NOT be used. In this case, the extended key
update fully replaces the standard key update functionality.

Implementations that receive a classic `KeyUpdate` message after
successfully negotiating the Extended Key Update functionality MUST
terminate the connection with an `"unexpected_message"` alert.

The extended key update is carried in a single handshake message named
`ExtendedKeyUpdate`, with an internal subtype indicating its role (request,
response, or new key update). The extended key update process can be
initiated by either peer after it has sent a `Finished` message.
Implementations that receive an `ExtendedKeyUpdate` message prior to
the sender having sent `Finished` MUST terminate the connection with
an `"unexpected_message"` alert.

The `KeyShareEntry` carried in a `ExtendedKeyUpdate(request)` and in
a `ExtendedKeyUpdate(response)` MUST use a group that was mutually
supported by the client and server during the initial handshake. An
implementation that receives an algorithm not previously negotiated
MUST terminate the connection with an `"illegal_parameter"` alert.

{{fig-key-update}} shows the interaction graphically. First, support
for the functionality in this specification is negotiated in the
`ClientHello` and the `EncryptedExtensions` messages. Then, the
`ExtendedKeyUpdate` exchange is sent to update the application traffic
secrets.

The extended key update exchange is performed between the initiator
and the responder; either the TLS client or the TLS server may act
as initiator.

~~~
       Client                                           Server

Key  ^ ClientHello
Exch | + key_share
     | + signature_algorithms
     v + extended_key_update   -------->
                                                  ServerHello  ^ Key
                                                  + key_share  | Exch
                                                               v
                                        {EncryptedExtensions   ^ Server
                                       + extended_key_update}  | Params
                                         {CertificateRequest}  v
                                                {Certificate}  ^
                                          {CertificateVerify}  | Auth
                                                   {Finished}  v
                               <--------
     ^ {Certificate}
Auth | {CertificateVerify}
     v {Finished}              -------->
       [Application Data]N     <------->  [Application Data]N
                                  ...
[ExtendedKeyUpdate(request)]N   -------->
                               <-------- [ExtendedKeyUpdate(response)]N
     [ExtendedKeyUpdate(new_key_update)]N   -------->
                                           <--------
                                   [ExtendedKeyUpdate(new_key_update)]N
                                  ...
       [Application Data]N+1   <------->  [Application Data]N+1

Legend:

    +   Indicates noteworthy extensions sent in the
    previously noted message.

    -   Indicates optional or situation-dependent
    messages/extensions that are not always sent.

    () Indicates messages protected using keys
    derived from a client_early_traffic_secret.

    {} Indicates messages protected using keys
    derived from a [sender]_handshake_traffic_secret.

    []N Indicates messages protected using keys
    derived from [sender]_application_traffic_secret_N.
~~~
{: #fig-key-update title="Extended Key Update Message Exchange in TLS 1.3."}

The `ExtendedKeyUpdate` wire format is:

~~~
enum {
   extended_key_update_request(0),
   extended_key_update_response(1),
   new_key_update(2),
   (255)
} ExtendedKeyUpdateType;

enum {
  accepted(0),
  retry(1),
  rejected(2),
  clashed(3),
  (255)
} ExtendedKeyUpdateResponseStatus;

struct {
   ExtendedKeyUpdateType update_type;
   select (update_type) {
      case extended_key_update_request: {
          KeyShareEntry key_share;
      }
      case extended_key_update_response: {
          ExtendedKeyUpdateResponseStatus status;
          select (status) {
             case accepted: KeyShareEntry key_share;
             case retry:    uint8 delay;
          }
      }
      case new_key_update: {
          /* empty */
      }
   };
} ExtendedKeyUpdate;
~~~

Fields:

* `update_type`: the subtype of the `ExtendedKeyUpdate` message.
* `key_share`: key share information. The contents of this field are
determined by the specified group and its corresponding definition
(see {{I-D.ietf-tls-rfc8446bis}}).
* `status`: response to an `extended_key_update_request`. Indicates
whether the responder accepted or declined the request.
* `delay`: delay in seconds for the initiator to retry the request
when status is set to `retry`.

There are three rejection reasons:

1. `retry`: request declined temporarily (responder is too busy).
In this case the message includes a `delay` in seconds. The initiator
MUST NOT retry within this interval and SHOULD retry after it elapses.
The responder MAY apply an overall rate limit not specific to a single
TLS session. If the initiator cannot proceed without an immediate
Extended Key Update it MUST terminate the connection with the TLS alert
`"extended_key_update_required"` (alert number TBD).

2. `rejected`: request declined permanently. The initiator MUST NOT
retry and, if it cannot proceed without Extended Key Update, MUST
terminate the connection with `"extended_key_update_required"`
(alert number TBD).

3. `clashed`: request declined because the responder has already
initiated its own extended key update.

# TLS 1.3 Considerations

The following steps are taken by a TLS 1.3 implementation; the steps
executed with DTLS 1.3 differ slightly.

1. The initiator sends `ExtendedKeyUpdate(request)` carrying a
`KeyShareEntry`. While an extended key update is in progress, the
initiator MUST NOT initiate another key update.

2. Upon receipt, the responder sends `ExtendedKeyUpdate(response)`.
If the responder accepts the request, it sets `status=accepted` and
includes its own `KeyShareEntry`. If the responder declines, it sets
an appropriate rejection status and omits the `KeyShareEntry`. While an extended
key update is in progress, the responder MUST NOT initiate another
key update.

3. Upon receipt of an `ExtendedKeyUpdate(response)` with
status to `accepted`, the initiator derives the new secrets from the
exchanged key shares. The initiator then sends an empty
ExtendedKeyUpdate(new_key_update) message to trigger the switch to the
new keys.

4. After the initiator sends `ExtendedKeyUpdate(new_key_update)` it
MUST update its send keys. Upon receipt of this message, the responder
MUST update its receive keys and then send
`ExtendedKeyUpdate(new_key_update)`, after which it MUST update its
send keys.

5. After receiving the responder’s `ExtendedKeyUpdate(new_key_update)`,
the initiator MUST update its receive keys.

Both sender and receiver MUST encrypt their
`ExtendedKeyUpdate(new_key_update)` messages with the old keys. Both
sides MUST ensure that the `new_key_update` encrypted with the old key
is received before accepting any messages encrypted with the new key.

If TLS peers independently initiate the extended key update and the
requests cross in flight, the `ExtendedKeyUpdate(request)` with the
lower lexicographic order of the `key_exchange` value in
`KeyShareEntry` MUST be rejected with status set to `clashed` in the
corresponding `ExtendedKeyUpdate(response)`. This prevents each
side from advancing keys by two generations.

The handshake framing uses a single `HandshakeType` for this message
(see {{fig-handshake}}).

~~~
      struct {
          HandshakeType msg_type;    /* handshake type */
          uint24 length;             /* bytes in message */
          select (Handshake.msg_type) {
              case client_hello:          ClientHello;
              case server_hello:          ServerHello;
              case end_of_early_data:     EndOfEarlyData;
              case encrypted_extensions:  EncryptedExtensions;
              case certificate_request:   CertificateRequest;
              case certificate:           Certificate;
              case certificate_verify:    CertificateVerify;
              case finished:              Finished;
              case new_session_ticket:    NewSessionTicket;
              case key_update:            KeyUpdate;
              case extended_key_update:   ExtendedKeyUpdate;
          };
      } Handshake;
~~~
{: #fig-handshake title="Handshake Structure."}

## TLS 1.3 Extended Key Update Example

While {{fig-key-update}} shows the high-level interaction between a
TLS 1.3 client and server, this section shows an example message exchange
with information about the updated keys added.

There are two phases:

1. The support for the functionality in this specification
is negotiated in the ClientHello and the EncryptedExtensions
messages.

2. Once the initial handshake is completed, a key update can be
triggered.

{{fig-key-update2}} provides an overview of the exchange starting
with the initial negotiation followed by the key update.

~~~
       Client                                           Server

Key  ^ ClientHello
Exch | + key_share
     | + signature_algorithms
     v + extended_key_update
                             -------->
                                                  ServerHello  ^ Key
                                                  + key_share  | Exch
                                                               v
                                        {EncryptedExtensions   ^ Server
                                       + extended_key_update}  | Params
                                         {CertificateRequest}  v
                                                {Certificate}  ^
                                          {CertificateVerify}  | Auth
                                                   {Finished}  v
                               <--------
     ^ {Certificate}
Auth | {CertificateVerify}
     v {Finished}              -------->
                                  ...
                              some time later
                                  ...
 [ExtendedKeyUpdate(request     -------->
  (with key_share))]
                               <-------- [ExtendedKeyUpdate(response
                                           (accepted, with key_share))]
                                        # Server derives new secrets
# Client derives new secrets			
 [ExtendedKeyUpdate(new_key_update)]
                               -------->
# Client updates SEND keys here
                                    # Server updates RECEIVE keys here
                               <--------
                                    [ExtendedKeyUpdate(new_key_update)]
                                    # Server updates SEND keys here

# Client updates RECEIVE keys here
~~~
{: #fig-key-update2 title="Extended Key Update Example."}

#  DTLS 1.3 Considerations

Unlike TLS 1.3, DTLS 1.3 implementations must take into account that handshake
messages are not transmitted over a reliable transport protocol.

Due to the possibility of an `ExtendedKeyUpdate(new_key_update)` message being
lost and thereby preventing the sender of that message from updating its keying
material, receivers MUST retain the pre-update keying material until receipt
and successful decryption of a message using the new keys.

Due to packet loss and/or reordering, DTLS 1.3 peers MAY receive records from an
earlier epoch. If the necessary keys are available, implementations SHOULD attempt
to process such records; however, they MAY choose to discard them.The exchange
has the following steps:

1. The initiator sends an `ExtendedKeyUpdate(request)` message, which contains a
   key share. While an extended key update is in progress, the initiator MUST NOT
   initiate further key updates.

2. On receipt of the `ExtendedKeyUpdate(request)`, the responder either accepts
   or declines the request. If the responder accepts the request, it sets the
   status in `ExtendedKeyUpdate(response)` to `accepted`, includes its own key
   share, and sets the local variable `accepted=1`. While an extended key update
   is in progress, the responder MUST NOT initiate further key updates. If the
   responder declines the request, it sets the status accordingly and does not
   include a key share. Declining the request aborts the exchange.

3. If the status in `ExtendedKeyUpdate(response)` was set to `accepted`,
   the responder transmits that message to the initiator.

4. On receipt of `ExtendedKeyUpdate(response)` with status `accepted`,
   the initiator sets the local variable `accepted=1` and derives a secret key based on the
   exchanged key shares. This message also serves as an implicit acknowledgment of the initiators’s ExtendedKeyUpdate(request), so no separate ACK is required.

5. The initiator transmits an `ExtendedKeyUpdate(new_key_update)` message.

6. Upon receiving `ExtendedKeyUpdate(new_key_update)`, the responder MUST update
   its receive keys and epoch value.

7. The responder acknowledges the received message by sending its own
   `ExtendedKeyUpdate(new_key_update)`.

8. After the initiator receives the responder’s `ExtendedKeyUpdate(new_key_update)`,
   the initiator MUST update its send key and epoch value. With the receipt of
   that message, the initiator MUST also update its receive keys.

9. The initiator MUST acknowledge the responder’s
   `ExtendedKeyUpdate(new_key_update)` with an ACK message.

10. On receipt of the ACK message, the responder updates its send key and epoch
    value. If this ACK is not received, the responder re-transmits ExtendedKeyUpdate(new_key_update) until ACK is received. The key update is complete once this ACK is processed by the responder.



## State Machine (Initiator)

The initiator starts in the START state with matching epochs (rx=tx=E).
It sends a Req and enters WAIT_RESP (updating=1). While waiting,
APP data may be sent at any time (tagged with the current tx) and received
according to the APP acceptance rule below.

If the responder returns Resp(false), the update aborts and the initiator
returns to FINISHED (no epoch change). If it returns Resp(true) with a
tag matching the current rx, the initiator sets `accepted=1` and derives
new key material. It then sends NKU still tagged with the old tx, moving to
SENT_NKU/WAIT_R_NKU.

Upon receiving the responder's NKU (tag equals the current rx, meaning
the responder is still tagging with its old tx), the initiator:

1. activates retention (old_rx=rx; retain_old=1),

2. increments both epochs (rx++, tx++),

3. sends ACK tagged with the new tx (which now equals the new rx),

4. clears updating and enters FINISHED.

Retention at the initiator ends automatically on the first APP received under
the new rx (then retain_old := 0). APP traffic is otherwise permitted at
any time; reordering is tolerated by the acceptance rule.

APP acceptance rule (receiver): accept if e == rx or
(retain_old && e == old_rx). If retain_old is set and an APP with the new
rx arrives, clear retain_old.

~~~
                       +---------------------+
                       |        START        |
                       | rx=tx=E, updating=0 |
                       +---------------------+
                                   |
                       (1) send Req [tag=tx]
                       set updating=1
                                   v
                          +----------------+
                          |   WAIT_RESP    |
                          |  (updating=1)  |
                          +----------------+
                         /|\  |          /|\ APP recv:
                          |   |           |  accept if e==rx
 APP send (anytime) ------+   |           |  or (retain_old &&
 (APP, tag=tx)                |           |     e==old_rx);
                              |           |  if e==rx and
                              |           |     retain_old: clear
                              |
                 Resp(false) -+      Resp(true, e==rx):
                |(reject)            (4) accepted=1
                |set updating=0      (5) send NKU [tag=old tx]
                +------------               v
                |         +----------------------+
                |         |  SENT_NKU /          |
                |         |  WAIT_R_NKU          |
                |         +----------------------+
                |                  |         /|\ APP send/recv
                |                  |             allowed
                |                  |
                |           (7) recv NKU [e==rx]
                |                  | (Responder still tags old tx)
                |                  v
                |         +----------------------+
                |         |  ACTIVATE RETENTION  |
                |         |  old_rx=rx;          |
                |         |  retain_old=1;       |
                |         |  rx=rx+1; tx=tx+1    |
                |         +----------------------+
                |                  |
                |       (9) send ACK [tag=tx]
                |       set updating=0; assert tx==rx
                |                  |
                +-----------+      |
                            v      v
                          +----------------+
 APP send/recv allowed -- |   FINISHED     |
 retain_old=0 afterwards  +----------------+
~~~

## State Machine (Responder)

The responder starts in the START state with synchronized transmit and receive epochs (rx=tx=E) and no update in progress. Application data can be sent at any time with the current transmit epoch and is accepted if the epoch matches the receiver's view or, if retention is active, the previous epoch.

Upon receiving an ExtendedKeyUpdate(request) (Req), the responder transitions to the RESPOND state, where it decides to either reject (acc=false, returning to FINISHED) or accept (acc=true). If accepted, it sets `accepted=1`, sends a positive response tagged with the current transmit epoch, and enters the WAIT_I_NKU state.

When a new_key_update (NKU) is received with the correct epoch, the responder activates retention mode: the old epoch is remembered, the receive epoch is incremented, and application data is accepted under both epochs for a transition period. The responder then sends its own NKU tagged with the old transmit epoch and moves to the WAIT_ACK state.

Finally, upon receipt of an ACK matching the updated epoch, the responder completes the transition by synchronizing transmit and receive epochs (tx=rx), disabling retention, and clearing the update flag. The state machine returns to FINISHED, ready for subsequent updates.

Throughout the process:

- Duplicate messages are tolerated (for retransmission handling).

- Temporary epoch mismatches are permitted while an update is in progress.

- Application data flows continuously, subject to epoch acceptance rules.

~~~
                          +---------------------+
                          |         START       |
                          | rx=tx=E, updating=0 |
                          +---------------------+
                           |  (3) recv Req [e==rx]
                           |  set updating=1
                           v
                        +----------------------+
                        |       RESPOND        |
                        | acc is true or false |
                        +----------+-----------+
                                   |
                 +-----------------+-----------------+
                 |                                   |
                 v                                   v
        (reject) acc=false                    (accept) acc=true
        send Resp(false)                      send Resp(true) [tag=tx]
        set updating=0                        set accepted=1
                 |                                   |
                 v                                   v
          +-------------+                     +---------------+
          |  FINISHED   |                     |  WAIT_I_NKU   |
          +-------------+                     | (updating=1)  |
                                              +-------+-------+
                                                      |
                                 (6) recv NKU [e==rx], assert accepted
                                                      |
                                                      v
                                           +---------------------+
                                           | ACTIVATE RETENTION  |
                                           | old_rx=rx;          |
                                           | retain_old=1; rx++  |
                                           +----------+----------+
                                                      |
                                         (7) send NKU [tag=old tx]
                                                      |
                                                      v
                                              +--------------+
                                              |  WAIT_ACK    |
                                              | (updating=1) |
                                              +-------+------+
                                                      |
                                       (8/9) recv ACK [e==rx]
                                       tx=rx; retain_old=0; updating=0
                                                      |
                                                      v
                                                +-----------+
                                                | FINISHED  |
                                                +-----------+
~~~

## DTLS 1.3 Extended Key Update Example

The following example illustrates a successful extended key update,
including how the epochs change during the exchange.

~~~
Client                            Server

  /---------------------------------------\
 |           Initial Handshake             |
  \---------------------------------------/

[C: tx=3, rx=3]                   [S: tx=3, rx=3]
[Application Data]               -------->
[C: tx=3, rx=3]                   [S: tx=3, rx=3]

[C: tx=3, rx=3]                   [S: tx=3, rx=3]
                                  <--------   [Application Data]
[C: tx=3, rx=3]                   [S: tx=3, rx=3]

  /---------------------------------------\
 |           Some time later ...           |
  \---------------------------------------/

[C: tx=3, rx=3]                   [S: tx=3, rx=3]
[ExtendedKeyUpdate(request)]     -------->
                                  # no epoch change yet

                           <-------- [ExtendedKeyUpdate(response)]
                                  # accepted; still old epochs

[ExtendedKeyUpdate(new_key_update)] -------->
# Sent under OLD epoch. Client does NOT bump yet.

# Step 6: responder bumps RECEIVE epoch on NKU-in:
# (rx:=rx+1; tx still old)
[C: tx=3, rx=3]                   [S: tx=3, rx=4]

                 <-------- [ExtendedKeyUpdate(new_key_update)]
# Responder’s NKU is tagged with OLD tx (3).

# Epoch switch point:
# Step 8: initiator bumps BOTH tx and rx on NKU-in:
[C: tx=4, rx=4]                   [S: tx=3, rx=4]

[ACK] (tag=new, tx==rx==4)        -------->

# Step 10: responder bumps SEND epoch on ACK-in:
[C: tx=4, rx=4]                   [S: tx=4, rx=4]

                                  <--------   [Application Data]
[C: tx=4, rx=4]                   [S: tx=4, rx=4]

[Application Data]                -------->
[C: tx=4, rx=4]                   [S: tx=4, rx=4]
~~~
{: #dtls-key-update title="Example DTLS 1.3 Extended Key Update: Message Exchange."}

{{dtls-table}} shows the steps, the message in flight, and the epoch changes on both sides.
The A/B -> X/Y notation indicates the change of epoch values for tx/rx before and after
the message transmission.

~~~
+-----+--------------------+-------------+-------+-------------+
|Step | Message            | Client tx/rx| Epoch | Server tx/rx|
+-----+--------------------+-------------+-------+-------------+
|  1  | APP ------------>  | 3/3 -> 3/3  |   3   | 3/3 -> 3/3  |
|  2  | <------------ APP  | 3/3 -> 3/3  |   3   | 3/3 -> 3/3  |
|  3  | req -------------> | 3/3 -> 3/3  |   3   | 3/3 -> 3/3  |
|  4  | <------------ resp | 3/3 -> 3/3  |   3   | 3/3 -> 3/3  |
|  5  | NKU  ------------> | 3/3 -> 3/3  |   3   | 3/3 -> 3/3  |
|  6  | <------------- NKU | 3/3 -> 3/3  |   3   | 3/3 -> 3/3  |
|  7  | ACK -------------> | 3/3 -> 4/4  |   4   | 3/3 -> 4/4  |
|  8  | <------------- APP | 4/4 -> 4/4  |   4   | 4/4 -> 4/4  |
|  9  | APP -------------> | 4/4 -> 4/4  |   4   | 4/4 -> 4/4  |
+-----+--------------------+-------------+-------+-------------+
~~~
{: #dtls-table title="Example DTLS 1.3 Extended Key Update: Epoch Changes."}


# Updating Traffic Secrets {#key_update}

When the extended key update message exchange is completed both peers
have successfully updated their application traffic secrets. The
key derivation function described in this document is used to perform
this update.

The design of the key derivation function for computing the next
generation of application_traffic_secret is motivated by the desire
to include

* a secret derived from the (EC)DHE exchange (or from the hybrid
key exchange / PQ-KEM exchange),
* a secret that allows the new key exchange to be cryptographically
bound to the previously established secret,
* the concatenation of the `ExtendedKeyUpdate(request)` and the
`ExtendedKeyUpdate(response)` messages, which contain the key shares,
binding the encapsulated shared secret ciphertext to IKM in case of
hybrid key exchange, providing MAL-BIND-K-CT security (see {{CDM23}}),
and
* new label strings to distinguish it from the key derivation used in
TLS 1.3.

The following diagram shows the key derivation hierarchy.

~~~
       Master Secret N
             |
             v
       Derive-Secret(., "key derived", "")
             |
             v
 (EC)DHE -> HKDF-Extract = Master Secret N+1
             |
             +-----> Derive-Secret(., "c ap traffic2",
             |                ExtendedKeyUpdate(request) ||
             |                ExtendedKeyUpdate(response))
             |                = client_application_traffic_secret_N+1
             |
             +-----> Derive-Secret(., "s ap traffic2",
             |                ExtendedKeyUpdate(request) ||
             |                ExtendedKeyUpdate(response))
             |                = server_application_traffic_secret_N+1
             |
             +-----> Derive-Secret(., "exp master2",
             |                ExtendedKeyUpdate(request) ||
             |                ExtendedKeyUpdate(response))
             |                = exporter_master_secret_N+1
             |
             +-----> Derive-Secret(., "res master2",
             |                ExtendedKeyUpdate(request) ||
             |                ExtendedKeyUpdate(response))
                              = resumption_master_secret_N+1
~~~

During the initial handshake, the Master Secret is generated (see
{{Section 7.1 of I-D.ietf-tls-rfc8446bis}}). Since the Master Secret
is discarded during the key derivation procedure, a derived value is
stored. This stored value then serves as the input salt to the first
key update procedure that incorporates the ephemeral (EC)DHE-
established value as input keying material (IKM) to produce
master_secret_{N+1}. The derived value from this new master secret
serves as input salt to the subsequent key update procedure, which
also incorporates a fresh ephemeral (EC)DHE value as IKM. This
process is repeated for each additional key update procedure.

The traffic keys are re-derived from
client_application_traffic_secret_N+1 and
server_application_traffic_secret_N+1, as described in
{{Section 7.3 of I-D.ietf-tls-rfc8446bis}}.

Once client_/server_application_traffic_secret_N+1 and its associated
traffic keys have been computed, implementations SHOULD delete
client_/server_application_traffic_secret_N and its associated
traffic keys as soon as possible. Note: The
client_/server_application_traffic_secret_N and its associated
traffic keys can only be deleted after receiving the
`ExtendedKeyUpdate(new_key_update)` message.

When using this extension, it is important to consider its interaction with
ticket-based session resumption. If resumption occurs without a new (EC)DH
exchange that provides forward secrecy, an attacker could potentially revert
the security context to an earlier state, thereby negating the benefits of
the extended key update. To preserve the security guarantees provided by key
updates, endpoints MUST either invalidate any session tickets issued prior
to the key update or ensure that resumption always involves a fresh (EC)DH
exchange.

If session tickets cannot be stored securely, developers SHOULD consider
disabling ticket-based resumption in their deployments. While this approach
may impact performance, it provides improved security properties.

# Post-Quantum Cryptography Considerations

Hybrid key exchange refers to the simultaneous use of multiple key
exchange algorithms, with the resulting shared secret derived by
combining the outputs of each. The goal of this approach is to maintain
security even if all but one of the component algorithms are later found
to be vulnerable.

The transition to post-quantum cryptography has motivated the adoption of
hybrid key exchanges in TLS, as described in
{{I-D.ietf-tls-hybrid-design}}. Specific hybrid groups
have been registered in {{I-D.ietf-tls-ecdhe-mlkem}}.
When hybrid key exchange is used, the `key_exchange` field of each
`KeyShareEntry` in the initial handshake is formed by concatenating
the `key_exchange` fields of the constituent algorithms. This same
approach is reused during the Extended Key Update, when new key
shares are exchanged.

The specification in {{I-D.ietf-tls-mlkem}} registers the lattice-based
ML-KEM algorithm and its variants, such as ML-KEM-512, ML-KEM-768 and
ML-KEM-1024. The KEM encapsulation key or KEM ciphertext is represented
as a 'KeyShareEntry' field. This same approach is reused during the
Extended Key Update, when new key shares are exchanged.

# SSLKEYLOGFILE Update

As a successful extended key update exchange invalidates previous secrets,
SSLKEYLOGFILE {{I-D.ietf-tls-keylogfile}} needs to be populated with new
entries. As a result, two additional secret labels are utilized in the
SSLKEYLOGFILE:

1. `CLIENT_TRAFFIC_SECRET_N+1`: identifies the
client_application_traffic_secret_N+1 in the key schedule

2. `SERVER_TRAFFIC_SECRET_N+1`: identifies the
server_application_traffic_secret_N+1 in the key schedule

Similar to other entries in the SSLKEYLOGFILE, the label is followed by the
32-byte value of the Random field from the ClientHello message that
established the TLS connection, and the corresponding secret encoded in
hexadecimal.

SSLKEYLOGFILE entries for the extended key update MUST NOT be produced if
SSLKEYLOGFILE was not used for other secrets in the handshake.

Note that each successful Extended Key Update invalidates all previous
SSLKEYLOGFILE secrets including past iterations of `CLIENT_TRAFFIC_SECRET_`
and `SERVER_TRAFFIC_SECRET_`.

# Exporter

Protocols such as DTLS-SRTP and DTLS-over-SCTP rely on TLS or DTLS for
key establishment, but reuse portions of the derived keying material for
their own specific purposes.These protocols use the TLS exporter defined
in {{Section 7.5 of I-D.ietf-tls-rfc8446bis}}.

Once the Extended Key Update mechanism is complete, such protocols would
need to use the newly derived key to generate Exported Keying Material
(EKM) to protect packets. The "sk" derived in the {{key_update}} will be
used as the "Secret" in the exporter function, defined in
{{Section 7.5 of I-D.ietf-tls-rfc8446bis}}, to generate EKM, ensuring that
the exported keying material is aligned with the updated security context.

#  Security Considerations

This entire document is about security.

# IANA Considerations

## TLS Alerts

IANA is requested to allocate value TBD for the "extended_key_update_required"
alert in the "TLS Alerts" registry. The value for the "DTLS-OK" column is "Y".

## TLS Flags

IANA is requested to add the following entry to the "TLS Flags"
extension registry {{TLS-Ext-Registry}}:

*  Value: TBD1
*  Flag Name: extended_key_update
*  Messages: CH, EE
*  Recommended: Y
*  Reference: [This document]

## TLS HandshakeType

IANA is requested to add the following entry to the "TLS HandshakeType"
registry {{TLS-Ext-Registry}}:

*  Value: TBD2
*  Description: extended_key_update
*  DTLS-OK: Y
*  Reference: [This document]

Note: The subtypes `extended_key_update_request`, `extended_key_update_response`,
and `new_key_update` are internal to the `ExtendedKeyUpdate` message and do not
require separate HandshakeType code points.

--- back

# Acknowledgments

We would like to thank the members of the "TSVWG DTLS for SCTP
Requirements Design Team" for their discussion. The members, in
no particular order, were:

*  Marcelo Ricardo Leitner
*  Zaheduzzaman Sarker
*  Magnus Westerlund
*  John Mattsson
*  Claudio Porfiri
*  Xin Long
*  Michael Tüxen
*  Hannes Tschofenig
*  K Tirumaleswar Reddy
*  Bertrand Rault

Additionally, we would like to thank the chairs of the
Transport and Services Working Group (tsvwg) Gorry Fairhurst and
Marten Seemann as well as the responsible area director Martin Duke.

Finally, we would like to thank Martin Thomson, Ilari Liusvaara,
Benjamin Kaduk, Scott Fluhrer, Dennis Jackson, David Benjamin,
Matthijs van Duin, Rifaat Shekh-Yusef, Joe Birr-Pixton, Eric Rescorla,
and Thom Wiggers for their review comments.
