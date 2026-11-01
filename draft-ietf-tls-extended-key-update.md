---
title: Extended Key Update for Transport Layer Security (TLS) 1.3

abbrev: Extended Key Update for TLS
docname: draft-ietf-tls-extended-key-update-latest
category: std
updates: 9261, 9846

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
      ins: T. Reddy
      name: Tirumaleswar Reddy
      email: kondtir@gmail.com
      org: Nokia
 -
      ins: M. Tüxen
      name: Michael Tüxen
      email: tuexen@fh-muenster.de
      org: Münster Univ. of Applied Sciences
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

informative:
  I-D.ietf-tls-ecdhe-mlkem:
  I-D.ietf-tls-mlkem:
  RFC9958:
  ANSSI:
     author:
        org: ANSSI
     title: Recommendations for securing networks with IPsec, Technical Report
     target: https://cyber.gouv.fr/sites/default/files/2012/09/NT_IPsec_EN.pdf
     date: August 2015
  TLS-Ext-Registry:
     author:
        org: IANA
     title: Transport Layer Security (TLS) Extensions
     target: https://www.iana.org/assignments/tls-extensiontype-values
     date: November 2023
  TLS-Param-Registry:
     author:
        org: IANA
     title: Transport Layer Security (TLS) Parameters
     target: https://www.iana.org/assignments/tls-parameters
     date: November 2023
  CCG16:
     author:
        org: IEEE
     title: "On Post-compromise Security"
     target: https://doi.org/10.1109/csf.2016.19
     date: August 2016


--- abstract

TLS 1.3 ensures forward secrecy by performing an ephemeral Diffie-Hellman key exchange
during the initial handshake, protecting past communications even if a party's
long-term keys (typically a private key with a corresponding certificate) are later
compromised.

While the built-in KeyUpdate mechanism allows application traffic keys to be refreshed
during a session, it does not incorporate fresh entropy from a new key exchange and
therefore does not provide post-compromise security. This limitation can pose a security
risk in long-lived sessions, such as those found in industrial IoT or telecommunications
environments.

To address this, this specification defines an extended key update mechanism that
performs a fresh execution of the key exchange negotiated during the initial handshake
within an active session, thereby providing post-compromise security. Interference by
a person-in-the-middle attacker during the exchange is detectable by the server when
post-handshake authentication is used, and by both peers when exported authenticators
are used.

By forcing attackers to exfiltrate new key material repeatedly, this approach mitigates
the risks associated with static key compromise. Regular renewal of session keys helps
contain the impact of such compromises. The extension is applicable to both TLS 1.3
and DTLS 1.3.

--- middle

#  Introduction

The Transport Layer Security (TLS) 1.3 protocol provides forward secrecy by using
fresh ephemeral key exchange during the initial handshake. In the base protocol,
this key exchange is performed with (EC)DHE. By registering new NamedGroup codepoints,
TLS specifications also define hybrid and post-quantum key exchange mechanisms for
the same purpose. This ensures that encrypted communication remains confidential even
if an attacker later obtains a party's long-term private key, protecting against passive
adversaries who record encrypted traffic for later decryption.

TLS 1.3 also includes a KeyUpdate mechanism that allows traffic keys to be refreshed
during an established session. However, this mechanism does not provide
post-compromise security, as it applies only a key derivation function to the
previous application traffic key as input. While this design is generally sufficient
for short-lived connections, it may present security limitations in scenarios where
sessions persist for extended periods, such as in industrial IoT or telecommunications
systems, where continuous availability is critical and session renegotiation or resumption
is impractical.

Earlier versions of TLS supported session renegotiation, which allowed peers to negotiate
fresh keying material, including performing new Diffie-Hellman exchanges during the
session lifetime. Due to protocol complexity and known vulnerabilities, renegotiation
was first restricted by {{?TLS-RENEGOTIATION=RFC5746}} and ultimately removed in TLS 1.3. While the
KeyUpdate message was introduced to offer limited rekeying functionality, it does
not fulfill the same cryptographic role as renegotiation and cannot refresh
the TLS main secret and consequently cannot derive new secrets from fresh key
exchange input. This limitation applies regardless of whether the session was
established with traditional (EC)DHE, a post-quantum/traditional (PQ/T) hybrid exchange,
or a post-quantum KEM exchange.

Security guidance from national agencies, such as ANSSI (France {{ANSSI}}), recommends the
periodic renewal of cryptographic keys during long-lived sessions to limit the
impact of key compromise. This approach encourages designs that force an
attacker to perform dynamic key exfiltration, as defined in {{?CONFIDENTIALITY=RFC7624}}. Dynamic
key exfiltration refers to attack scenarios where an adversary must repeatedly
extract fresh keying material to maintain access to protected data, increasing
operational cost and risk for the attacker. In contrast, static key exfiltration,
where the TLS main secret is extracted once and reused, poses a greater long-term
threat, especially when session keys are not refreshed with fresh key exchange input
rather than key derivation.

This specification defines a TLS extension that introduces an extended key update
mechanism for sessions established with traditional (EC)DHE, hybrid
PQ/T hybrid key exchange, or post-quantum KEM exchange. Unlike the
standard key update, this mechanism allows peers to inject fresh key exchange
input from the negotiated mechanism into an active session. By periodically
rerunning the negotiated key exchange, this extension enables the derivation of
new traffic keys. Compromise of prior traffic keys does not suffice to
derive the new traffic keys. As noted in
{{Appendix F of !TLS=RFC9846}},
this approach mitigates the risk of static key exfiltration and shifts the attacker
burden toward dynamic key exfiltration.

The proposed extension is applicable to both TLS 1.3 {{TLS}} and DTLS 1.3  {{!DTLS=RFC9147}}. For clarity,
the term "TLS" is used throughout this document to refer to both protocols unless
otherwise specified.

# Terminology and Requirements Language {#term}

{::boilerplate bcp14-tagged}

To distinguish the key update procedure defined in {{TLS}}
from the key update procedure specified in this document, we use the terms
"standard key update" and "extended key update", respectively.

For terminology regarding traditional and PQ/T hybrid algorithms please
see {{?RFC9794}}.

In this document, we use the term post-compromise security, as defined in
{{CCG16}}. We assume that an adversary may obtain
access to the application traffic keys.

Unless otherwise specified, all references to traffic keys in this document
refer to application traffic keys and because the Extended Key Update procedure
occurs after the handshake phase has completed, no handshake traffic keys
are involved.

In this document, send key refers to the \[sender\]_write_key, and receive key
refers to the \[receiver\]_write_key. These keys are derived from the active
client_application_traffic_secret_N and server_application_traffic_secret_N,
as defined in (D)TLS 1.3 {{TLS}}, and are replaced with new ones
after each successful Extended Key Update.

# Negotiating the Extended Key Update

Client and servers use the TLS flags extension
{{!TLS-FLAGS=I-D.ietf-tls-tlsflags}} to indicate support for the functionality
defined in this document.  We call this flag "Extended_Key_Update"
flag.

The "Extended_Key_Update" flag proposed by the client in the
ClientHello (CH) MUST be acknowledged in the EncryptedExtensions
(EE), if the server also supports the functionality defined in this
document and is configured to use it.

If the "Extended_Key_Update" flag is not set, servers ignore any of the
functionality specified in this document and applications that
require post-compromise security will have to initiate a full
handshake.

# Extended Key Update Messages {#ext-key-update}

If the client and server agree to use the extended key update mechanism,
the standard key update MUST NOT be used. In this case, the extended key
update fully replaces the standard key update functionality.

Implementations that receive a classic `KeyUpdate` message after
successfully negotiating the Extended Key Update functionality MUST
terminate the connection with an `"unexpected_message"` alert.

The extended key update messages are signaled in a new handshake message named
`ExtendedKeyUpdate` (EKU), with an internal uint8 message subtype indicating its role.
This specification defines three ExtendedKeyUpdate message subtypes:

- `key_update_request` (0)
- `key_update_response` (1)
- `key_update_finish` (2)

New ExtendedKeyUpdate message subtypes are assigned by IANA as described in {{iana-eku-registry}}.

A TLS peer which receives a ExtendedKeyUpdate with an unexpected message subtype MUST
abort the connection with an `"unexpected_message"` alert.

The extended key update process can be initiated by either peer after it has
sent a `Finished` message. Implementations that receive an `ExtendedKeyUpdate`
message prior to the sender having sent `Finished` MUST terminate the connection with
an `"unexpected_message"` alert.

The `KeyShareEntry` carried in a `key_update_request` and in
a `key_update_response` MUST use the group that was negotiated by the client
and server during the initial handshake. An implementation that receives an
algorithm other than previously negotiated MUST terminate the connection
with an `"illegal_parameter"` alert.

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
  [EKU(key_update_request)]N   -------->
                               <--------  [EKU(key_update_response)]N
   [EKU(key_update_finish)]N   -------->
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
   key_update_request(0),
   key_update_response(1),
   key_update_finish(2),
   (255)
} ExtendedKeyUpdateType;

struct {
   ExtendedKeyUpdateType eku_type;
   select (eku_type) {
      case key_update_request: {
          KeyShareEntry key_share;
      }
      case key_update_response: {
          KeyShareEntry key_share;
      }
      case key_update_finish: {
          /* empty */
      }
   };
} ExtendedKeyUpdate;
~~~

Fields:

* `eku_type`: the subtype of the `ExtendedKeyUpdate` message.
* `key_share`: key share information. The contents of this field is
determined by the specified group and its corresponding definition
(see {{Section 4.2.8 of TLS}}).

# TLS 1.3 Considerations {#TLSC}

The following steps are taken by a TLS 1.3 implementation; the steps
executed with DTLS 1.3 differ slightly.

1. The initiator sends `ExtendedKeyUpdate(key_update_request)` carrying a
`KeyShareEntry`. While an extended key update is in progress, the
initiator MUST NOT initiate another key update.

1. Upon receipt, the responder sends its own `KeyShareEntry` in a
`ExtendedKeyUpdate(key_update_response)` message. While an extended
key update is in progress, the responder MUST NOT initiate another
key update. The responder MAY defer sending a response if system load or resource
constraints prevent immediate processing. In such cases, the response MUST
be sent once sufficient resources become available.

1. After the responder sends the `ExtendedKeyUpdate(key_update_response)` it
MUST update its send keys.

1. Upon receipt of an `ExtendedKeyUpdate(key_update_response)` the initiator
derives the new secrets from the exchanged key shares. The initiator then updates
its receive keys and sends an empty ExtendedKeyUpdate(key_update_finish) message to
complete the process. The initiator MUST NOT defer derivation of the secrets and
sending the ExtendedKeyUpdate(key_update_finish) message as it would stall the
communication.

1. After sending `ExtendedKeyUpdate(key_update_finish)`, the initiator MUST update its
send keys.

1. Upon receiving the initiator’s `ExtendedKeyUpdate(key_update_finish)`,
the responder MUST update its receive keys.

Both initiator and responder MUST encrypt their `ExtendedKeyUpdate` messages
using the old keys. The Responder MUST ensure that it has received `ExtendedKeyUpdate(key_update_finish)`,
encrypted with the old key, before accepting any messages encrypted with the new keys.

If TLS peers independently initiate the extended key update and the
requests cross in flight, the `ExtendedKeyUpdate(key_update_request)` with the
lower lexicographic order of the `key_exchange` value in
`KeyShareEntry` MUST be ignored. It MUST NOT be included in the
transcript hash. This prevents each
side from advancing keys by two generations. If the tie-break comparison yields
equality (an event that should be impossible for genuine
asymmetric key pairs), the endpoint MUST treat this as a protocol violation,
send an "unexpected_message" alert, and close the connection.

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
{: #fig-handshake title="TLS 1.3 Handshake Structure."}

## TLS 1.3 Extended Key Update Example

{{fig-key-update}} shows the high-level interaction between a TLS 1.3 client
and server, while {{fig-key-update2}} illustrates an example message exchange
including the updated keys. Similar to the `key_update message`, the
`extended_key_update` message can be sent by either peer after sending its
Finished message.

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
 [EKU(key_update_request       -------->
       (with key_share))]
                               <-------- [EKU(key_update_response
                                           (with key_share))]
                                        # Server derives new secrets
                                        # and updates SEND keys here
# Client derives new secrets
# and updates RECEIVE keys here
     [EKU(key_update_finish)]  -------->
# Client updates SEND keys here
                                    # Server updates RECEIVE keys here
~~~
{: #fig-key-update2 title="Extended Key Update Example."}

#  DTLS 1.3 Considerations {#DTLSC}

Unlike TLS 1.3, DTLS 1.3 implementations must take into account that handshake
messages are not transmitted over a reliable transport protocol. The responder
updates its send keys only after receiving `ExtendedKeyUpdate(key_update_finish)`,
which confirms that the initiator has derived the new keys. The initiator updates
its send keys and sending epoch only after receiving an ACK that acknowledges
`ExtendedKeyUpdate(key_update_finish)`. This ensures that a record sent by the
initiator under the new keys also confirms receipt of that ACK, allowing the
responder to stop retaining the old receive keys for EKU retransmissions.

EKU messages MUST be transmitted reliably, like other DTLS handshake messages.
If necessary, EKU messages MAY be fragmented as described in {{Section 5.5 of DTLS}}.
Due to the possibility of EKU messages or their acknowledgments being lost,
receivers MUST retain the pre-update keying material until receipt
and successful decryption of a message using the new keys.

Due to packet loss and/or reordering, DTLS 1.3 peers MAY receive records from an
earlier epoch. If the necessary keys are available, implementations SHOULD attempt
to process such records; however, they MAY choose to discard them.

The exchange has the following steps:

1. The initiator sends an `ExtendedKeyUpdate(key_update_request)` message, which contains a
   key share. While an extended key update is in progress, the initiator MUST NOT
   initiate further key updates. This message is subject to DTLS handshake
   retransmission, but delivery is only confirmed when the initiator either receives the
   corresponding `ExtendedKeyUpdate(key_update_response)` or an ACK.

1. Upon receipt, the responder sends its own `KeyShareEntry` in a
   `ExtendedKeyUpdate(key_update_response)` message. While an extended key update
   is in progress, the responder MUST NOT initiate further key updates. The responder MAY defer
   sending a response if system load or resource constraints prevent immediate processing.
   In such cases, the responder MUST acknowledge receipt of the key_update_request with an ACK and, once
   sufficient resources become available and the ordering requirements below
   are satisfied, send the key_update_response and
   retransmit it until acknowledged by the initiator. The responder MUST also
   defer the response while earlier independent handshake transmissions remain
   unacknowledged, as specified in {{dtls-handshake-ordering}}, and MUST
   acknowledge the request while waiting. A late ACK for the request does not
   change the EKU state after the corresponding response has been processed.
   Other records covered by that ACK MUST still be handled according to the
   DTLS acknowledgment procedures.

1. On receipt of `ExtendedKeyUpdate(key_update_response)` the initiator derives a secret key based on the
   exchanged key shares. This message also serves as an implicit acknowledgment of the
   initiator's `ExtendedKeyUpdate(key_update_request)`, so no separate ACK is required. The initiator MUST
   update its receive keys and epoch value. The initiator MUST NOT defer derivation of the secrets.

1. The initiator transmits an `ExtendedKeyUpdate(key_update_finish)` message
   using its pre-update send keys and epoch. This message is subject to DTLS
   retransmission until acknowledged. All retransmissions MUST use the same
   epoch and keying material as the original transmission, as specified in
   {{Section 4.2.1 of DTLS}}.

1. Upon receiving the initiator's `ExtendedKeyUpdate(key_update_finish)`,
   the responder MUST update its send and receive keys and their epoch values.
   This message implicitly acknowledges the corresponding
   `ExtendedKeyUpdate(key_update_response)`.

1. The responder MUST acknowledge the received message by sending an ACK
   protected with its updated send keys and epoch. While retaining the
   pre-update receive keys, the responder MUST process and acknowledge
   retransmissions of `ExtendedKeyUpdate(key_update_finish)`, including when
   it has already initiated a subsequent PHA exchange.

1. On receipt of an ACK protected with the responder's updated send keys that
   acknowledges `ExtendedKeyUpdate(key_update_finish)`, the initiator MUST
   update its send keys and sending epoch. Acknowledgment is determined from
   the ACK's record numbers as specified in {{Section 7.2 of DTLS}}; the epoch
   of the ACK alone is not sufficient. The initiator stops retransmitting
   `ExtendedKeyUpdate(key_update_finish)` and the EKU exchange is locally
   complete. Until this acknowledgment is received, the initiator MUST NOT
   send any records using the new keys or sending epoch, including ACK
   records, and MUST continue the DTLS retransmission procedure for
   `ExtendedKeyUpdate(key_update_finish)`.

The ordering and acknowledgment requirements in {{dtls-handshake-ordering}}
and {{dtls-transition-acks}} apply throughout this exchange.

## Handshake Ordering Across an EKU {#dtls-handshake-ordering}

Before sending `ExtendedKeyUpdate(key_update_request)`, the initiator MUST
wait until its earlier independent handshake transmissions have been
acknowledged, explicitly or by the response defined for their respective
exchange. The responder MUST satisfy the same requirement before sending
`ExtendedKeyUpdate(key_update_response)`. If this delays the response, the
responder acknowledges the request as specified in Step 2 of {{DTLSC}}.
This requirement concerns acknowledgment of transmitted handshake messages,
not completion of every operation they might request. In particular, an
acknowledged `RequestConnectionId` need not already have been fulfilled by
the delivery of new CIDs.

A responder waiting for those earlier acknowledgments MUST also defer
new independent handshake transmissions, subject to the PHA exception
below. It continues retransmitting already outstanding messages.

From sending its request until completing Step 7, the initiator MUST defer
new independent handshake transmissions. From sending its response until
receiving `ExtendedKeyUpdate(key_update_finish)` and updating its sending
epoch, the responder MUST do likewise. The exception for completing a PHA
exchange whose request crosses an EKU request is specified in
{{pha-eku-ordering}}. Any handshake transmissions made for that exception
MUST be acknowledged before the initiator sends EKU finish or the responder
sends EKU response, respectively. Processing a crossed EKU request follows
the EKU collision rules and is not blocked by these restrictions.

`ExtendedKeyUpdate(key_update_finish)` is the initiator's last new
handshake message in its pre-update sending epoch.
`ExtendedKeyUpdate(key_update_response)` is the responder's last new
handshake message in its pre-update sending epoch. An endpoint that receives
a new handshake message in that epoch with a `message_seq` greater than
the corresponding closing message MUST terminate the connection with an
`unexpected_message` alert. Retransmissions and reordered earlier messages
are distinguished using the DTLS handshake sequencing procedures and MUST
NOT be treated as violations of this rule merely because they arrive later.
EKU does not reset the handshake `message_seq` counter.

These restrictions do not prohibit retransmissions, ACK records, or
application data. Retransmissions MUST use the original epoch and keying
material. An endpoint MUST continue processing ACKs and retransmissions
needed to complete outstanding transmissions while waiting to send an EKU
message. Explicit ACKs acknowledge only the records they identify; an ACK
for an independent handshake message does not complete EKU unless it also
acknowledges EKU finish as required by Step 7.

## Acknowledgments During the Epoch Transition {#dtls-transition-acks}

The new sending epoch at the initiator is not available for sending records
until Step 7, even though the secrets have already been derived. The initiator
can receive records under the new receive keys while waiting for this ACK.

The initiator MUST defer explicit acknowledgment of handshake records
received in the new epoch until it has processed the ACK for EKU finish and
activated its new sending epoch. It MUST NOT acknowledge those records
under the old sending epoch or activate the new sending epoch early to
acknowledge them. This is a specific deferral of the ACK behavior described
in {{Sections 7 and 7.1 of DTLS}}. Once Step 7 completes, outstanding
acknowledgments are generated according to the DTLS procedures, including
any applicable implicit acknowledgment by a responding flight. An ACK
whose record numbers reference an epoch higher than the epoch of the ACK
record MUST be rejected by terminating the connection with an
`illegal_parameter` alert.

Deferring acknowledgment does not necessarily defer message processing.
Implementations MUST maintain the normal DTLS reassembly and handshake
sequencing procedures. They MAY accept and sequence a message while
buffering the operation it requests, provided they retain its contents and
the context needed for subsequent processing. Operation-specific rules
determine whether further processing must wait. For example, the client
defers PHA processing of a new-epoch `CertificateRequest` as specified in
{{dtls-pha-wait-ack}}. Application-layer operations, such as Exported
Authenticators, instead follow the context-selection rules in
{{post-handshake-context}} and do not generate DTLS handshake ACKs when
carried in application data.

Connection-ID processing is independent of the traffic-key transition.
When a `NewConnectionId` with `cid_immediate` is processed, the new CID
MUST be used as required by {{Section 9 of DTLS}}, including for subsequent
EKU retransmissions that still use the old epoch and keys. Such records
are newly protected with the appropriate header and record number. A CID
change MUST NOT be treated as evidence that EKU finish has been acknowledged.
CID lookup and retention of the old receive keys MUST allow the required
EKU retransmissions to reach the appropriate connection state.

Implementations MAY impose limits on buffering during the transition. If
a message or fragment cannot be processed or retained, its record MAY be
discarded without acknowledgment, allowing retransmission to recover it.
Records whose handshake contents have been neither processed nor buffered
MUST NOT be acknowledged. Reception during this transition alone MUST NOT
be treated as an `unexpected_message` error; other message validity and
ordering requirements remain in effect.

Neither deferred processing nor deferred acknowledgments may suspend the
EKU retransmission procedure or prevent processing of the ACK for EKU
finish. The initiator MUST continue retransmitting finish under the old
keys and epoch, and the responder MUST continue processing and acknowledging
those retransmissions while retaining the old receive keys. Receipt of
another new-epoch message MUST NOT be treated as an implicit acknowledgment
of EKU finish.

## Handshake Message Format

The handshake framing uses a single `HandshakeType` for this message
(see {{fig-dtls-handshake}}).

~~~
       enum {
           client_hello(1),
           server_hello(2),
           new_session_ticket(4),
           end_of_early_data(5),
           encrypted_extensions(8),
           request_connection_id(9),
           new_connection_id(10),
           certificate(11),
           certificate_request(13),
           certificate_verify(15),
           finished(20),
           key_update(24),
           extended_key_update(TBD),  /* new */
           message_hash(254),
           (255)
       } HandshakeType;

       struct {
           HandshakeType msg_type;    /* handshake type */
           uint24 length;             /* bytes in message */
           uint16 message_seq;        /* DTLS-required field */
           uint24 fragment_offset;    /* DTLS-required field */
           uint24 fragment_length;    /* DTLS-required field */
           select (msg_type) {
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
               case request_connection_id: RequestConnectionId;
               case new_connection_id:     NewConnectionId;
           } body;
       } DTLSHandshake;
~~~
{: #fig-dtls-handshake title="DTLS 1.3 Handshake Structure."}

## DTLS 1.3 Extended Key Update Example

The following example illustrates a successful extended key update,
including how the epochs change during the exchange.

~~~
Client                            Server
(Initiator)                       (Responder)

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
[EKU(key_update_request)]  -------->
                                  # no epoch change yet

                           <-------- [EKU(key_update_response)]
# Sent under OLD epoch. Server does NOT bump yet.

# Step 3: initiator bumps RECEIVE epoch on
# receiving key update response-in:
# (rx:=rx+1; tx still old)
[C: tx=3, rx=4]                   [S: tx=3, rx=3]

[EKU(key_update_finish)]   -------->
# Sender's Fin is tagged with OLD tx (3).
# Initiator retains OLD tx until Fin is acknowledged.
[C: tx=3, rx=4]                   [S: tx=3, rx=3]

# Step 5: responder bumps BOTH tx and rx on Fin-in:
[C: tx=3, rx=4]                   [S: tx=4, rx=4]

                           <-------- [ACK] (tag=new)

# Step 7: ACK of Fin stops retransmission and bumps SEND epoch.
[C: tx=4, rx=4]                   [S: tx=4, rx=4]

[Application Data]         -------->
[C: tx=4, rx=4]                   [S: tx=4, rx=4]

                           <--------   [Application Data]
[C: tx=4, rx=4]                   [S: tx=4, rx=4]
~~~
{: #dtls-key-update title="Example DTLS 1.3 Extended Key Update: Message Exchange."}

{{dtls-table}} shows the steps, the message in flight, and the epoch changes on both sides.
The A/B -> X/Y notation indicates the change of epoch values for tx/rx before and after
the message transmission.

~~~
+--------------------+----------------+--------------+
| Message            | Client tx/rx   | Server tx/rx |
+--------------------+----------------+--------------+
| APP ------------>  | 3/3 -> 3/3     | 3/3 -> 3/3   |
| <------------ APP  | 3/3 -> 3/3     | 3/3 -> 3/3   |
| req -------------> | 3/3 -> 3/3     | 3/3 -> 3/3   |
| <------------ resp | 3/3 -> 3/4     | 3/3 -> 3/3   | <- step 3
| Fin  ------------> | 3/4 -> 3/4     | 3/3 -> 4/4   | <- step 5
| <------------- ACK | 3/4 -> 4/4     | 4/4 -> 4/4   | <- step 7
| APP -------------> | 4/4 -> 4/4     | 4/4 -> 4/4   |
| <------------- APP | 4/4 -> 4/4     | 4/4 -> 4/4   |
+--------------------+----------------+--------------+
~~~
{: #dtls-table title="Example DTLS 1.3 Extended Key Update: Epoch Changes."}


# Updating Traffic Keys {#key_update}

When the extended key update message exchange is completed both peers
have successfully updated their application traffic keys. The
key derivation function described in this document is used to perform
this update.

The design of the key derivation function for computing the next
generation of application_traffic_secret is motivated by the desire
to include

* a secret derived from the negotiated key exchange, whether (EC)DHE, post-quantum KEM, or a PQ/T hybrid mechanism,
* a secret that allows the new key exchange to be cryptographically
bound to the previously established secret,
* a transcript hash that is updated after each Extended Key Update exchange by
hashing the previous transcript hash together with the current
ExtendedKeyUpdate(key_update_request) and
ExtendedKeyUpdate(key_update_response) messages. This binds any
encapsulation ciphertext and public key used in PQ/T hybrid or post-quantum key exchanges
to the IKM and cryptographically binds the newly derived secrets to the
original handshake transcript, all prior EKU exchanges, the current EKU
exchange, and the corresponding KEM public key and encapsulation ciphertext, and
* new label strings to distinguish it from the key derivation used in
TLS 1.3.

The transcript_hash_N denotes the transcript hash value associated with
generation N. During each Extended Key Update exchange, the transcript
hash value for the next generation is computed as follows:

~~~

 transcript_hash_N+1 = Transcript-Hash(transcript_hash_N ||
                                       EKU(key_update_request) ||
                                       EKU(key_update_response))
~~~

Once transcript_hash_N+1 has been computed, transcript_hash_N can be deleted.
No prior transcript hash values need to be retained for future EKU exchanges.
transcript_hash_0 denotes the transcript hash of the initial TLS handshake,
covering all messages from the ClientHello up to and including the
client Finished message.

`main_secret_N` denotes the Main Secret (see {{Section 7.1 of TLS}})
associated with generation N.

{{key-hierarchy}} shows the key derivation hierarchy.

~~~
       main_secret_N
             |
             v
       Derive-Secret(., "derived", "")
             |
Shared       v
Secret -> HKDF-Extract = main_secret_N+1
             |
             +-----> Derive-Secret(., "c ap traffic",
             |                     transcript_hash_N+1)
             |                = client_application_traffic_secret_N+1
             |
             +-----> Derive-Secret(., "s ap traffic",
             |                     transcript_hash_N+1)
             |                = server_application_traffic_secret_N+1
             |
             +-----> Derive-Secret(., "exp master",
             |                     transcript_hash_N+1)
             |                = exporter_secret_N+1
~~~
{: #key-hierarchy title="Key Derivation Hierarchy."}

During the initial handshake, the Main Secret is generated (see
{{Section 7.1 of TLS}}). Since the main_secret
is discarded during the key derivation procedure, a derived value is
stored. This stored value then serves as the input salt to the first
key update procedure that incorporates the shared secret as input
keying material (IKM) to produce main_secret_N+1. The derived value
from this new main secret serves as input salt to the subsequent key
update procedure, which also incorporates a fresh shared secret as
IKM. This process is repeated for each additional key update procedure.

The shared secret is determined by the negotiated key exchange mechanism.
In the base protocol, this mechanism is (EC)DHE (see {{Section 7.4 of
TLS}}). Post-quantum and hybrid key exchange mechanisms derive the
shared secret as specified by their respective definitions. See also
{{pqc-cons}}.

The traffic keys are re-derived from
client_application_traffic_secret_N+1 and
server_application_traffic_secret_N+1, as described in
{{Section 7.3 of TLS}}.

Once client_/server_application_traffic_secret_N+1 and its associated
traffic keys have been computed, implementations SHOULD delete
client_/server_application_traffic_secret_N and its associated
traffic keys as soon as possible. Note: The
client_/server_application_traffic_secret_N and its associated
traffic keys can only be deleted by the responder after receiving the
`ExtendedKeyUpdate(key_update_finish)` message.

Once client_/server_application_traffic_secret_N+1 and the corresponding traffic
keys are in use, all subsequent records, including alerts and post-handshake
messages MUST be protected using those keys.

When using this extension, it is important to consider its interaction with
PSK-based resumption using PSKs established via the NewSessionTicket mechanism
defined in {{TLS}}.

EKU provides post-compromise recovery for the TLS connection in which it is performed.
The recovery guarantees depend on the assumed compromise model. In typical deployment
environments, PSKs established via the NewSessionTicket mechanism are generated and
reside in memory within the rich operating system. Although such PSKs may subsequently
be stored in secure storage, they are exposed during this initial processing window,
and compromise of endpoint memory during this period is sufficient to reveal them.
Consequently, later protection using secure storage does not prevent their prior
compromise. These PSKs are sufficient to establish new authenticated TLS connections.
Even if an implementation invalidates previously issued PSKs upon completion of the
EKU exchange, an attacker that has already obtained such a PSK may initiate and
complete a resumed session prior to that invalidation. In such environments, EKU does
not prevent the use of previously issued PSKs.

Accordingly, endpoints that enable EKU MUST disable resumption using PSKs established
via the NewSessionTicket mechanism. `resumption_main_secret_N+1` is not
derived for this reason in {{key-hierarchy}}.

When this extension has been successfully negotiated, the server MUST NOT
send `NewSessionTicket` messages on the connection. The client MUST silently
ignore otherwise valid `NewSessionTicket` messages received on that connection
and MUST NOT retain or use the tickets for session resumption. Receipt of
such a message MUST NOT, by itself, cause the client to terminate the
connection. Other applicable requirements for message validity and ordering
remain in effect.

For DTLS, ignoring a `NewSessionTicket` does not exempt it from handshake
sequencing, reassembly, or acknowledgment, including for fragments and
retransmissions. The client MUST follow {{dtls-transition-acks}}, including
deferring acknowledgment of new-epoch ticket records while awaiting the
ACK for `ExtendedKeyUpdate(key_update_finish)`. Ignoring a ticket MUST NOT
prevent processing of subsequent handshake messages.

# Post-Quantum Cryptography Considerations {#pqc-cons}

The shared secret used by the Extended Key Update mechanism is derived according
to the negotiated key exchange method. As a result, this specification supports
the same classes of key establishment mechanisms as TLS itself, including traditional
Diffie-Hellman-based key exchanges, post-quantum key encapsulation mechanisms (KEMs),
and hybrid combinations thereof.

In the base TLS protocol, the shared secret is typically established using (EC)DHE
(see {{Section 7.4 of TLS}}). Recent extensions have introduced support for post-quantum
and hybrid key establishment mechanisms to facilitate the transition to post-quantum
cryptography. The rationale for this transition and the associated terminology are
discussed in {{RFC9958}} and {{RFC9794}}, respectively.

For hybrid mechanisms such as SecP256r1MLKEM768, defined in {{I-D.ietf-tls-ecdhe-mlkem}},
the shared secret is derived by combining the outputs of the constituent algorithms;
specifically, it is the concatenation of the ECDHE and ML-KEM shared secrets. For
ML-KEM-only key exchange, as defined in {{I-D.ietf-tls-mlkem}}, the ML-KEM shared
secret is provided directly to the TLS key schedule in place of the (EC)DHE shared
secret.

The Extended Key Update protocol reuses the key exchange representation defined by the
negotiated mechanism. Consequently, the exchange of fresh key shares during an Extended
Key Update follows the same encoding and shared-secret derivation rules as the
corresponding TLS handshake. For KEMs, the initiator generates the encapsulation key
and the responder performs encapsulation against it, regardless of which peer acted
as the TLS client or server during the initial handshake.

# SSLKEYLOGFILE Update

As a successful extended key update exchange invalidates previous secrets,
SSLKEYLOGFILE {{?TLS-KEYLOGFILE=I-D.ietf-tls-keylogfile}} needs to be populated with new
entries. As a result, three additional secret labels are utilized in the
SSLKEYLOGFILE:

1. `CLIENT_TRAFFIC_SECRET_N+1`: identifies the
client_application_traffic_secret_N+1 in the key schedule

1. `SERVER_TRAFFIC_SECRET_N+1`: identifies the
server_application_traffic_secret_N+1 in the key schedule

1. `EXPORTER_SECRET_N+1`: identifies the
exporter_secret_N+1 in the key schedule

Similar to other entries in the SSLKEYLOGFILE, the label is followed by the
32-byte value of the Random field from the ClientHello message that
established the TLS connection, and the corresponding secret encoded in
hexadecimal.

SSLKEYLOGFILE entries for the extended key update MUST NOT be produced if
SSLKEYLOGFILE was not used for other secrets in the handshake.

Note that each successful Extended Key Update invalidates all previous
SSLKEYLOGFILE secrets including past iterations of `CLIENT_TRAFFIC_SECRET_`,
`SERVER_TRAFFIC_SECRET_` and `EXPORTER_SECRET_`.

# Exporter

## Post-Compromise Security for the Initial Exporter Secret

The TLS 1.3 Key Schedule, see Figure 5 of {{TLS}}, derives the exporter_secret from the main secret. This
exporter_secret is static for the lifetime of the connection and is not updated by a standard key update.

A core design goal of this specification is not met if the exporter_secret does not change.
Therefore, this document defines an exporter interface that derives a fresh exporter secret
whenever new application traffic keys are updated through the EKU. Prior to the first
Extended Key Update, this interface uses an initial exporter secret, denoted
exporter_secret_0.

If exporter_secret_0 were identical to exporter_secret, which is retained
for the lifetime of the connection, a later compromise of exporter_secret
would reveal all keying material exported under exporter_secret_0, even
after exporter_secret_0 is discarded.

Therefore, exporter_secret_0 MUST be distinct from the exporter_secret. This separation
ensures that compromise of the TLS exporter interface does not compromise outputs
derived from the exporter interface defined in this document.

exporter_secret_0 is derived from the Main Secret and the handshake transcript. It uses
the label "exporter eku" rather than "exp master", because "exp master" with the Main
Secret yields the TLS exporter_secret. exporter_secret_N+1 uses "exp master" with
main_secret_N+1 (see {{key-hierarchy}}). exporter_secret_0 is computed as follows:

~~~~
exporter_secret_0 =
Derive-Secret(Main Secret,
"exporter eku",
Transcript-Hash(ClientHello..server Finished))
~~~~

Applications that require post-compromise security MUST use the exporter
interface defined in this document. This exporter interface is independent of
the TLS exporter defined in {{Section 7.5 of TLS}}, which continues to use a
static `exporter_secret` for the lifetime of the connection for compatiblity with "legacy" applications.

## Exporter Usage After Extended Key Update

Protocols such as DTLS-SRTP and DTLS-over-SCTP rely on TLS or DTLS for
key establishment, but reuse portions of the derived keying material for
their own specific purposes. These protocols use the TLS exporter defined
in {{Section 7.5 of TLS}}. Exporters are also used for deriving
authentication related values such as nonces, as described in {{!RFC9729}}.

Once the Extended Key Update mechanism is complete, such protocols would
need to use the newly derived exporter secret to generate Exported Keying Material
(EKM) to protect packets. The exporter_secret_N+1 derived in
{{key_update}} will be used as the "Secret" in the exporter function, defined in
{{Section 7.5 of TLS}}, to generate EKM, ensuring that the exported keying material
is aligned with the updated security context. Compromise of a previous exporter secret does not suffice to derive
exporter_secret_N+1.

When a new exporter secret becomes active following a successful Extended
Key Update, the TLS or DTLS implementation would have to provide an
asynchronous notification to the application indicating that:

* A new epoch has become active, and the (D)TLS implementation can
  include the corresponding epoch identifier. Applications receiving an
  epoch identifier can use it to request keying material for that
  specific epoch through an epoch-aware exporter interface.
  In TLS, this identifier represents a local logical counter that may differ between peers.

Applications are notified that a new exporter generation is active when
EKU completes locally. This notification reports local availability; it
does not establish that the peer has already completed EKU or that an
earlier application operation has completed.

* In TLS, the initiator triggers notification after Step 5 in {{TLSC}},
  and the responder triggers notification after Step 6 in {{TLSC}}.
* In DTLS, the initiator triggers notification to the application
  after Step 7 in {{DTLSC}}, and the responder triggers notification
  after Step 6 in {{DTLSC}}.

The corresponding EKM is obtained by the application through the TLS/DTLS exporter
interface using its chosen label and context values as defined in {{Section 7.5 of TLS}}.

The retention policy for exporter secrets and derived application contexts
is application-specific and MUST satisfy {{post-handshake-context}}.
An operation using an older exporter generation can remain outstanding
after newer-generation data has been processed. Neither that event nor
retirement of old DTLS record keys alone determines when the operation's
exporter context may be discarded. Applications MUST bound retention and
define how expired operations fail. For example, a DTLS-SRTP application
might retain an older packet-protection context while its replay window
still accepts packets protected with that context, as described in
{{Section 3.3.2 of !RFC3711}}.


# Interaction with Post-Handshake Operations {#exported}

EKU changes traffic secrets, exporter secrets, and the transcript context
used by subsequent authentication. Operations that depend on that state
need both consistent context selection and suitable ordering across the
change. This section defines common requirements and illustrates them with
Post-Handshake Certificate-Based Client Authentication (PHA), carried by
the handshake protocol, and Exported Authenticators, carried by an
application protocol. The additional DTLS transmission and acknowledgment
rules are specified in {{dtls-handshake-ordering}} and
{{dtls-transition-acks}}.

EKU provides fresh traffic secrets, but EKU alone does not authenticate that both endpoints
derived the same updated keys. An attacker that temporarily compromises an endpoint
may later act as a person-in-the-middle attacker capable of interfering with the EKU exchange.
Such an attacker can cause the peers to transition to divergent traffic secrets without detection,
but cannot compromise the endpoint to derive secrets after the new epoch is established.
TLS 1.3 provides two mechanisms that can detect such divergence, each with a different scope.
Post-Handshake Certificate-Based Client Authentication authenticates the client to the server,
and therefore allows only the server to detect divergence. Exported Authenticators {{!RFC9261}}
authenticate the endpoint that produces the authenticator, so detection at both endpoints
requires an authenticator in each direction.

## Binding Operations to a Key Generation {#post-handshake-context}

Post-handshake operations that use changing key material or transcript
state MUST have an unambiguous association with the generation and context
used to create and verify their authentication values. Advancing EKU MUST
NOT silently change the context of an outstanding operation. Generation
selection is separate from the epoch of the records carrying the operation:
an authentication object can be created before an EKU and transmitted or
verified after it.

Here, a generation identifies the relevant secrets and transcript context
of the initial connection or of a particular EKU exchange. Generation
identifiers are scoped to their connection and MUST NOT be used to select
a context belonging to another connection.

This requirement can be satisfied by ordering the operation and EKU so
that the context remains fixed, or by explicitly selecting a generation
and retaining the corresponding context. PHA uses the ordering rules in
{{pha-eku-ordering}} to keep its transcript and Finished key consistent.
The epoch-aware Exported Authenticator interface in {{eku-ea}} instead
selects an exporter generation for each operation, allowing the operation
to overlap an EKU without changing that selection.

The protocol using an explicitly selected generation MUST specify how
both endpoints associate the operation with the same generation, how that
association is authenticated, and which generations are acceptable for its
purpose. A local epoch counter alone is not sufficient unless the protocol
defines how the peer interprets it. A valid authentication value from an
older generation MUST NOT be treated as proof of authentication under the
updated context. Applications that use authentication to check the result
of a particular EKU MUST require the generation resulting from that EKU.

An implementation MUST either retain the keying material or derived
context needed by an outstanding operation for its permitted lifetime, or
explicitly fail that operation if the context becomes unavailable. It
MUST NOT substitute a different generation. Applications MUST define
bounded lifetimes for such operations. Selection, buffering, or expiration
of an application operation MUST NOT prevent the underlying EKU exchange
from progressing. These requirements do not require indefinite retention
of old exporter secrets.

## Post-Handshake Certificate-Based Client Authentication

When Post-Handshake Certificate-Based Client Authentication (Section 4.7.2 of {{TLS}}) is
performed after an Extended Key Update (EKU) is complete, the Handshake Context used for
the transcript hash is updated. It consists of transcript_hash_N+1 concatenated
with the CertificateRequest message. The Finished message is computed using a
MAC key derived from the Base Key of the new epoch (client_application_traffic_secret_N+1).
Because the CertificateVerify message is signed with the private key corresponding to the
client's end-entity certificate over this Handshake Context, the server can detect divergent
key state. Post-Handshake Authentication does not reauthenticate the server, so the client gains
no equivalent assurance. A client that requires such assurance can request an Exported
Authenticator from the server.

## Exported Authenticators {#eku-ea}

This document extends Section 5.1 of {{!RFC9261}} with an epoch-aware
Exported Authenticator interface. For this interface, the Handshake Context
and Finished MAC Key MUST be derived from `exporter_secret_G` for the
explicitly selected exporter generation G. The same generation MUST be
used for creation and validation of an authenticator, even if another EKU
completes between those operations. The derivation labels and authenticator
construction otherwise follow {{RFC9261}}.

Implementations supporting this interface MUST allow the application to
select the generation for both creation and validation. For a requested
authenticator, the requesting application MUST select the generation when
constructing the request, and the responding application MUST use that
generation. For an unsolicited server authenticator, the generating
application selects it. In both cases, the application protocol MUST
unambiguously identify the generation to the verifier and bind it to the
authenticated operation as required by {{post-handshake-context}}.

The `certificate_request_context` can carry this identification as part of
an application-defined encoding. That encoding MUST preserve the context's
length limits, uniqueness requirements, and request-response association
from {{RFC9261}}. It MUST identify the same exporter generation at both
endpoints; a bare local counter that the peer cannot interpret is
insufficient. This specification does not define a common wire encoding
for application protocols.

If the selected generation is unknown, unavailable, expired, or disallowed
by application policy, creation or validation MUST fail explicitly rather
than use the current exporter or retry with a different generation. As an
exception, if the generation is not yet locally available because EKU is
still in progress, the implementation MAY defer the operation within its
permitted lifetime instead of immediately failing it. Such deferral MUST
NOT block processing of EKU messages or acknowledgments.
These failures are application-operation failures and do not, by
themselves, require termination of the (D)TLS connection.

An application checking for key divergence after an EKU MUST select the
generation resulting from that EKU. If interference has caused the peers
to derive different exporter secrets for that generation, the authenticator
cannot be successfully validated as specified in {{Section 5.2.4 of RFC9261}}.
Accepting an older-generation authenticator would not establish agreement
on the newly derived secrets.

The existing interfaces in {{RFC9261}} retain their use of the static TLS
exporter defined in {{Section 7.5 of TLS}}. They MUST NOT silently switch to
the epoch-aware interface. As discussed in {{Section 7 of RFC9261}}, the
epoch-aware interface can also be implemented at the application layer
using the corresponding exporter interface.

Authenticator requests and authenticators are carried by an application
protocol, not as TLS or DTLS handshake messages. Carrying them in DTLS
application data does not create a DTLS handshake acknowledgment obligation.
Application-level delivery and acknowledgment requirements are defined by
the application protocol. The record epoch carrying an authenticator MUST
NOT, by itself, determine the exporter generation used to validate it.

## Ordering of Authentication and Extended Key Update {#pha-eku-ordering}

EKU and Post-Handshake Authentication may both occur during the lifetime
of a (D)TLS connection.  Post-Handshake Certificate-Based Client
Authentication (PHA) is bound to the handshake transcript and computes
its `Finished` message as specified in {{Section 4.5.3 of TLS}}, using a key
derived from the application traffic secret that is active at the time
the `CertificateRequest` is sent. Therefore, specific ordering constraints
are required to preserve cryptographic consistency.

### Post-Handshake Certificate-Based Client Authentication

Except for the deferred processing of a new-epoch `CertificateRequest`
specified in {{dtls-pha-wait-ack}}, an endpoint MUST NOT complete an EKU
exchange in a manner that transitions to new application traffic secrets
while a PHA exchange is in progress.

The following constraints apply to both TLS 1.3 and DTLS 1.3:

* An endpoint MUST NOT initiate PHA while an EKU exchange is locally in progress.

* An endpoint MUST NOT initiate an EKU exchange while a PHA exchange is
  outstanding.

* In a cross-flight condition, if a (D)TLS client sends an EKU request and,
  before receiving a response, receives a `CertificateRequest` from the
  (D)TLS server, the endpoints MUST defer completion of the EKU exchange
  and proceed with the Post-Handshake Authentication exchange. The endpoints
  MUST NOT transition to new application traffic secrets until the
  authentication exchange has completed.

In DTLS, deferred EKU request is acknowledged as specified in {{DTLSC}}.

#### DTLS CertificateRequest Received Before the EKU ACK {#dtls-pha-wait-ack}

When the DTLS client initiates EKU, the server can complete its part of the
exchange by receiving `ExtendedKeyUpdate(key_update_finish)`, updating its
keys, and sending the ACK. The server can then initiate PHA by sending a
`CertificateRequest` under the new epoch. Loss or reordering of the ACK can
cause this request to reach the client while the client is still waiting
for acknowledgment of `ExtendedKeyUpdate(key_update_finish)`.

Subject to the buffering limits in {{dtls-transition-acks}}, the client
MUST buffer the successfully decrypted
`CertificateRequest` and defer its PHA processing until the ACK acknowledging
`ExtendedKeyUpdate(key_update_finish)` has been processed. This also applies
to retransmissions and fragments of the `CertificateRequest`. Receipt of
this request MUST NOT be treated as an `unexpected_message` error or as an
implicit acknowledgment of `ExtendedKeyUpdate(key_update_finish)`.

The general acknowledgment deferral in {{dtls-transition-acks}} applies
to records carrying this `CertificateRequest`, including its fragments and
retransmissions. Once EKU completes locally, the request is
acknowledged explicitly or implicitly by the PHA response according to
{{Sections 7 and 7.1 of DTLS}}.

Buffering the request MUST NOT suspend EKU retransmissions or prevent
processing of the EKU ACK. The client MUST continue retransmitting
`ExtendedKeyUpdate(key_update_finish)` under the pre-update keys and epoch
according to the DTLS retransmission procedure. The server MUST continue
processing and acknowledging those retransmissions as specified in
{{DTLSC}}, even while awaiting the PHA response.

For the ordering constraints in this section, this deferred request does
not prevent the client from completing the EKU exchange. Once the client
has processed the ACK acknowledging `ExtendedKeyUpdate(key_update_finish)`,
it MUST update its send keys and sending epoch before processing the
buffered request. The client MUST use the resulting new epoch for its PHA
response records. The PHA Handshake Context MUST use the transcript updated
by this EKU, and the PHA `Finished` MAC key MUST be derived from the
corresponding new `client_application_traffic_secret_N+1`, as described
above. Neither endpoint may initiate another EKU until this PHA exchange
has completed, as required by the preceding constraints.

These rules apply to a new-epoch `CertificateRequest` received while the
client awaits the EKU ACK. They do not change the preceding rule for a
`CertificateRequest` from the pre-update epoch that crosses an EKU request
before receipt of the EKU response.

The following example shows recovery when the first EKU ACK is lost:

~~~
Client (EKU initiator)                  Server (EKU responder)

         <---------------------------- EKU(response) [N]
rx := N+1; tx remains N
EKU(finish) [N] --------------------->
                                       rx := N+1; tx := N+1
         X---------------------------- ACK of EKU(finish) [N+1]
                                       (ACK lost)
         <---------------------------- CertificateRequest [N+1]
Buffer request; defer PHA and its ACK
EKU(finish) [N] --------------------->  (retransmission)
         <---------------------------- ACK of EKU(finish) [N+1]
tx := N+1; stop EKU retransmissions
Process buffered CertificateRequest
Certificate [N+1] ------------------->
CertificateVerify* [N+1] ------------>
Finished [N+1] ---------------------->
         <---------------------------- ACK of PHA response [N+1]
~~~
{: #dtls-pha-after-ack title="DTLS PHA Deferred Until the EKU ACK Is Received."}

### Exported Authenticators

An Exported Authenticator operation using the epoch-aware interface may
overlap EKU only with the fixed generation association and context handling
specified in {{post-handshake-context}} and {{eku-ea}}. An epoch-aware API
alone does not ensure that the peer selects the same generation. The
application protocol's generation agreement is required as well.

No additional serialization between EKU and such an operation is required
when those conditions are satisfied. An operation bound to an older
generation can complete after EKU, but does not authenticate the new
generation. If the operation selects the new generation before it becomes
available at the peer, its processing may need to wait while EKU proceeds.

#  Security Considerations

This section discusses additional security and operational aspects introduced by the Extended Key Update mechanism. All security considerations of TLS 1.3 {{TLS}} and DTLS 1.3 {{!DTLS=RFC9147}} continue to apply.

## Scope of Key Compromise {#scope}

Extended Key Update (EKU) assumes a transient compromise of an endpoint, in
which the attacker obtains the keying material held by that endpoint for the connection,
including the current application traffic secrets and the values retained for deriving
subsequent secrets, but not the long-term private key. It does not address a persistent
attacker on the device with ongoing access to key material.
The EKU procedure does not rely on long-term private keys, which may be stored in a
secure element (e.g., a Hardware Security Module (HSM)) or within the rich OS.
Moreover, in security‑critical scenarios, these long‑term private keys are typically
stored separately from the primary secret or the traffic keys.

Two threat scenarios are relevant:

1. The long-term private key remains secure, while application traffic keys in the
rich operating system are temporarily exposed. EKU addresses this case for the current
TLS connection.

2. If the long-term private key in the rich OS is compromised, EKU can still protect
the current TLS connection by updating the main secret and traffic keys. However, all
future TLS connections are at risk, as the attacker can impersonate the endpoint using
the stolen private key.

Extended Key Update can restore confidentiality only if the attacker no longer
has access to either peer. If an adversary retains access to current application traffic
keys and can act as a person-in-the-middle attacker during the Extended Key Update, then the
update cannot restore security. The interference is detectable as described in {{exported}}.

If one of the mechanisms defined in {{exported}} is not used, the attacker can
impersonate each endpoint, substitute EKU messages, and maintain control
of the communication. When Post-Handshake Certificate-Based Client
Authentication or the modified Exported Authenticator mechanism is used, the
authentication messages include a CertificateVerify message signed with a private key
the attacker does not hold. Any modification or substitution of EKU messages therefore
becomes detectable.

If a compromise occurs before the handshake completes, the ephemeral key exchange,
client_handshake_traffic_secret, server_handshake_traffic_secret, and the initial
client_/server_application_traffic_secret could be exposed. In that case, only the
initial handshake messages and the application data encrypted under the initial
client_/server_application_traffic_secret can be decrypted until the Extended Key
Update procedure completes. The Extended Key Update procedure derives fresh
application_traffic_secrets from a new ephemeral key exchange.

## Post-Compromise Security

Under the compromise model described in this document, Extended Key Update
provides post-compromise security for long-lived TLS sessions.
To ensure post-compromise security guarantees each update MUST use freshly generated
ephemeral key exchange material. Implementations MUST NOT reuse ephemeral key
exchange material across updates or across TLS sessions.

## Denial-of-Service (DoS)

The Extended Key Update mechanism increases computational and state-management overhead. A malicious peer could attempt to exhaust CPU or memory resources by initiating excessive update requests.

Implementations SHOULD apply the following mitigations:

* Limit the frequency of accepted Extended Key Update requests per session.
* A peer that has sent an Extended Key Update MUST NOT initiate another until the previous update completes.
  If a peer violates this rule, the receiving peer MUST treat it as a protocol violation, send an "unexpected_message" alert, and terminate the connection.

## Operational Guidance

Deployments SHOULD evaluate Extended Key Update performance under load and fault conditions, such as high-frequency or concurrent updates. TLS policies SHOULD define explicit rate limits that balance post-compromise security benefits against potential DoS exposure.

# IANA Considerations

## TLS Flags

IANA is requested to add the following entry to the "TLS Flags"
extension registry {{TLS-Ext-Registry}}:

*  Value: TBD1
*  Flag Name: extended_key_update
*  Messages: CH, EE
*  Recommended: Y
*  Reference: This document

## TLS HandshakeType

IANA is requested to add the following entry to the "TLS HandshakeType"
registry {{TLS-Param-Registry}}:

*  Value: TBD2
*  Description: extended_key_update
*  DTLS-OK: Y
*  Reference: This document

## ExtendedKeyUpdate Message Subtypes Registry {#iana-eku-registry}

IANA is requested to create a new registry "TLS ExtendedKeyUpdate Message Subtypes", within the existing "Transport Layer Security (TLS) Parameters" registry group
{{TLS-Param-Registry}}.
This new registry reserves types used for Extended Key Update entries.
The initial contents of this registry are as follows.

| Value | Description | DTLS-OK | Reference |
| --- | --- | --- | --- |
| 0 | key_update_request | Y | This document |
| 1 | key_update_response | Y | This document |
| 2 | key_update_finish | Y | This document |
| 3-255 | Unassigned | | |

New assignments in the "TLS ExtendedKeyUpdate Message Subtypes" registry will be administered by
IANA through Specification Required procedure {{?RFC8126}}.  The role of the
designated expert is described in {{Section 17 of ?RFC8447}}.  The designated expert
{{RFC8126}} ensures that the specification is publicly available.  It is sufficient to
have an Internet-Draft (that is posted and never published as an RFC) or to cite a
document from another standards body, industry consortium, or any other location.
An expert may provide more in-depth reviews, but their approval should not be taken as an
endorsement of the ExtendedKeyUpdate Message Subtype.

## SSLKEYLOGFILE labels

IANA is requested to add the following entries to the "TLS SSLKEYLOGFILE Labels"
extension registry {{TLS-Ext-Registry}}:

| Value | Description | Reference | Comment |
| --- | --- | --- | --- |
| CLIENT_TRAFFIC_SECRET_N+1 | Secret protecting client records after Extended Key Update | This document | N represents iteration of Extended Key Update |
| SERVER_TRAFFIC_SECRET_N+1 | Secret protecting server records after Extended Key Update | This document | N represents iteration of Extended Key Update |
| EXPORTER_SECRET_N+1 | Exporter secret after Extended Key Update | This document | N represents iteration of Extended Key Update |

--- back

# Acknowledgments

We would like to thank the members of the "TSVWG DTLS for SCTP
Requirements Design Team" for their discussion. The members, in
no particular order, were: Marcelo Ricardo Leitner, Xin Long,
John Mattsson, Claudio Porfiri, Bertrand Rault, K Tirumaleswar Reddy,
Zaheduzzaman Sarker, Hannes Tschofenig, Michael Tüxen, and
Magnus Westerlund.

Additionally, we would like to thank the chairs of the
Transport and Services Working Group (tsvwg) Gorry Fairhurst and
Marten Seemann as well as the responsible area director Martin Duke.

Finally, we would like to thank David Benjamin, Joe Birr-Pixton,
Matthijs van Duin, Scott Fluhrer, Dennis Jackson, Benjamin Kaduk,
Ilari Liusvaara, Eric Rescorla, Rifaat Shekh-Yusef, Martin Thomson,
Mathy Vanhoef, and Thom Wiggers for their review comments.

# State Machines

The sections below describe the state machines for the extended key update
operation for TLS 1.3 and DTLS 1.3.

The state machine diagrams in the Appendix are provided for illustrative
purposes only to aid understanding of the protocol flow. They are not normative.
In case of any discrepancy between the Appendix diagrams and the protocol
behavior specified in the main body of this document, the text in the
draft takes precedence.

For editorial reasons we abbreviate the protocol message types:

 * Req - ExtendedKeyUpdate(request)
 * Resp - ExtendedKeyUpdate(response)
 * Fin - ExtendedKeyUpdate(key_update_finish)
 * ACK - Acknowledgement message from {{Section 7 of DTLS}}
 * APP - application data payloads

In the (D)TLS 1.3 state machines discussed below, the terms SEND and RECEIVE keys
refer to the send and receive key variables defined in {{term}}.

The TLS state machine diagrams use the following notation:

* Numbered labels (1), (2), … denote normal protocol transitions in the order they occur.
* Lettered labels (A), (B), … denote exceptional or conditional transitions.
* Self-loops indicate that the state does not change as a result of the event.

## TLS 1.3 State Machines

This section describes the initiator and responder state machines.

### Initiator State Machine

~~~ aasvg
+----------------------+
| START                |
| send_key=current,    |
| receive_key=current  |
| updating=0           |
+----------------------+
      |
(1) send Req with local KeyShareEntry
    set updating=1
      v
+----------------------+
| WAIT_RESP            |
| updating=1           |
+----------------------+
|  \
|   \ (A) recv peer Req (crossed updates):
|    \  compare peer.key_exchange to local.key_exchange
|     \  - if peer < local: IGNORE peer Req (send nothing)
|      \ - if peer == local: ABORT "unexpected_message"
|       \ - if peer > local: ABANDON local update:
|          * set updating=0
|          * act as RESPONDER: send Resp with KeyShareEntry,
|            derive new secrets, then proceed as in responder flow
|
|  (2) recv Resp with key_share:
|      derive new secrets
|      send Fin (encrypted under old keys)
|      update SEND key (send_key := new)
|      update RECEIVE key (receive_key := new)
|      set updating=0
       v
+----------------------+
| FINISHED             |
+----------------------+
~~~

Notes:

- Fin message is sent under old keys.
- If a classic KeyUpdate arrives (EKU negotiated), ABORT "unexpected_message".
- Crossed-requests: ignore the request with LOWER lexicographic key_exchange; if equal, abort.

### Responder State Machine

~~~ aasvg
+----------------------+
| START                |
| send_key=current,    |
| receive_key=current  |
| updating=0           |
+----------------------+
      |
(1) recv Req
    set updating=1
      v
+----------------------+
| RESPOND              |
+----------------------+
|  send Resp with KeyShareEntry
|  (may defer sending if under load;
|   must send once resources free)
|  derive new secrets
|  update SEND keys (send_key := new)
|  --> WAIT_I_FIN
      v
+----------------------+
| WAIT_I_FIN           |
| updating=1           |
+----------------------+
      |
(2) recv Fin (encrypted under old keys)
    update RECEIVE keys (receive_key := new)
    set updating=0
      v
+----------------------+
| FINISHED             |
+----------------------+
~~~

Notes:

- Responder may defer Resp under load (no status reply), then must send it once resources are free.
- If a classic KeyUpdate arrives (EKU negotiated), ABORT "unexpected_message".

## DTLS 1.3 State Machines

This section describes the initiator and responder state machines.
The diagrams show the EKU message exchange. Sending actions are additionally
subject to {{dtls-handshake-ordering}}, including waiting for earlier
independent handshake transmissions to be acknowledged and deferring new
independent transmissions. Incoming messages and deferred operations follow
{{dtls-transition-acks}} and {{post-handshake-context}}. Those requirements
apply even where a diagram does not show a separate waiting state.

### Terms and Abbreviations

The following variables and abbreviations are used in the state machine diagrams.

- rx - current, accepted receive epoch.
- tx - current transmit epoch used for tagging outgoing messages.
- E - initial epoch value.
- updating - true while a key-update handshake is in progress.
- old_rx - the previous receive epoch remembered during retention.
- retain_old - when true, receiver accepts tags old_rx and rx.
- tag=... - the TX-epoch value written on an outgoing message.
- e==... - the epoch tag carried on an incoming message (what the peer sent).
- FINISHED / START / WAIT_RESP / WAIT_I_FIN / WAIT_R_FIN / ACTIVATE RETENTION / RESPOND / WAIT_ACK - diagram states; FINISHED denotes the steady state after success.

Crossed requests. If both peers independently initiate the extended key update and the key_update_request messages cross in flight, compare the KeyShareEntry.key_exchange values. The request with the lower lexicographic value must be ignored. If the values are equal, the endpoint must abort with an "unexpected_message" alert. If the peer's value is higher than the local one, the endpoint abandons its in-flight update and processes the peer's request as responder.

### State Machine (Initiator)

The initiator starts in the START state with matching epochs (rx := E; tx := E).
Once its earlier independent handshake transmissions have been acknowledged,
it sends a Req and enters WAIT_RESP (updating := 1). New independent
handshake transmissions are deferred until local completion, subject to
the PHA cross-flight exception in {{pha-eku-ordering}}. While waiting, APP
data may be sent at any time (tagged with the current tx) and received
according to the APP acceptance rule below.

Once the responder returns Resp with a tag matching the current rx, the initiator derives new key material. The initiator activates retention mode: the old epoch is remembered, the receive epoch is incremented, and application data is accepted under both epochs for a transition period. It then sends Fin still tagged with the old tx and enters WAIT_ACK without changing its transmit epoch.

If a peer key_update_request arrives while in WAIT_RESP (crossed updates), apply the crossed-request rule above. If the peer's key_exchange is higher, abandon the local update (updating := 0) and continue as responder: send key_update_response, derive new secrets, then proceed with the responder flow. If lower, ignore the peer's request; if equal, abort with "unexpected_message".

Upon receiving the responder's ACK under the updated epoch that acknowledges Fin, the initiator updates its transmit epoch (tx := rx), stops retransmitting Fin, disables retention, and clears the update flag. Matching the ACK's epoch alone does not acknowledge Fin. The state machine returns to FINISHED.

If the initiator is the DTLS client and receives a CertificateRequest under the
new epoch in WAIT_ACK, it buffers the request and defers both PHA processing
and acknowledgment of that request. Fin retransmissions under the old tx
continue. After processing the ACK of Fin, the client processes the buffered
request using the new epoch and the updated PHA context, as specified in
{{dtls-pha-wait-ack}}. It does not initiate another EKU while that PHA is pending.

Other new-epoch handshake records are acknowledged only after the ACK of
Fin has been processed. Their processing follows {{dtls-transition-acks}};
in particular, a CID change does not change tx or acknowledge Fin.

Throughout the process:

* Duplicate messages are tolerated (for retransmission handling).
* Temporary epoch mismatches are permitted while an update is in progress.
* Application data flows continuously, subject to epoch acceptance rules.

~~~ aasvg
+---------------------------------+
| START                           |
| rx := E; tx := E, updating := 0 |
+---------------------------------+
      |
(1) send Req [tag=tx]
    set updating := 1
      v
+------------------------------+
| WAIT_RESP                    |
+------------------------------+
 ^    ^    ^           ^
 |    |    |           |
 |    |    |           |
 |    |    |           +-- (A) recv peer Req (crossed):
 |    |    |                if peer < local  -> IGNORE (Self-Loop)
 |    |    |                if peer == local -> ABORT  (Error)
 |    |    |                if peer > local  -> ABANDON update;
 |    |    |                                    updating := 0;
 |    |    |                                    act as RESPONDER
 |    |    |
 |    |    +-- APP send (anytime)           (Self-Loop)
 |    |
 |    +-- APP recv: retain_old && e == old_rx   (Self-Loop)
 |
 +-- APP recv: e == rx                           (Self-Loop)

          | recv Resp [e == rx]
          | derive secrets
          v
+---------------------+
| ACTIVATE RETENTION  |
| old_rx=rx;          |
| retain_old=1; rx++  |
+---------------------+
          |
(2) send Fin [tag=old tx]
          v
+------------------------------+
| WAIT_ACK (updating = 1)      |
+------------------------------+
      |
      |  APP send/recv allowed (send with old tx)
      |  Client: buffer CertificateRequest [e==rx];
      |          defer PHA and its ACK
      |  Timeout: retransmit Fin [tag=old tx]
      |
(3) recv ACK of Fin [e==rx]
    tx=rx; retain_old=0; updating := 0
      v
+------------------------------------------+
| FINISHED                                 |
+------------------------------------------+
~~~

### State Machine (Responder)

The responder starts in the START state with synchronized transmit and receive epochs (rx := E; tx := E) and no update in progress. Application data can be transmitted at any time using the sender's current transmit epoch. A receiver must accept application data if the epoch tag on the DTLS record equals the receiver's current receive epoch. If the receiver has retention active (retain_old == true), the receiver must also accept DTLS records whose epoch tag equals the remembered previous epoch.

Upon receiving an `ExtendedKeyUpdate(key_update_request)` (Req), the responder
transitions to RESPOND. It waits for acknowledgment of earlier independent
handshake transmissions before sending `ExtendedKeyUpdate(key_update_response)`
and may also defer the response under load. While deferring, it acknowledges
the request. When sent, the response is tagged with the current tx and is
retransmitted until acknowledged explicitly or implicitly by Fin. It is
the last new handshake message in that sending epoch. New independent
handshake transmissions wait until Fin is received and the sending epoch
is updated, as specified in {{dtls-handshake-ordering}}.

After an `ExtendedKeyUpdate(key_update_finish)` (Fin) is received with the correct epoch, the responder:

1. activates retention (old_rx := rx; retain_old := 1),
1. increments both epochs (rx++, tx++),
1. sends ACK tagged with the new tx (which now equals the new rx),
1. clears updating and enters FINISHED.

In FINISHED, while retaining the old receive keys, the responder accepts
retransmissions of Fin under the old epoch and sends a new ACK under its
current tx. This also applies when the responder is the DTLS server and has
already sent a CertificateRequest for a subsequent PHA exchange.

Retention at the responder ends automatically on the first APP received under the new rx (then retain_old := 0). APP traffic is otherwise permitted at any time; reordering is tolerated by the acceptance rule.

APP acceptance rule (receiver): accept if e == rx or (retain_old && e == old_rx). If retain_old is set and an APP with the new rx arrives, clear retain_old.

~~~ aasvg
+---------------------------------+
| START                           |
| rx := E; tx := E, updating := 0 |
+---------------------------------+
      |
(1) recv Req [e==rx]
    set updating := 1
      v
+----------------------+
| RESPOND              |
+----------------------+
      |
      | send Resp [tag=tx]
      | (may defer; if deferred, ACK Req and later retransmit Resp
      |  until acknowledged by the initiator)
      v
+---------------+
| WAIT_I_FIN    |
| (updating=1)  |
+-------+-------+
      |
(2) recv Fin [e==rx]      (assert accepted)
      |
+---------------------+
| ACTIVATE RETENTION  |
| old_rx=rx;          |
| retain_old=1;       |
| rx=rx+1; tx=tx+1    |
+----------+----------+
      |
(3) send ACK [tag=tx]
    set updating := 0; assert tx==rx
      v
+------------------------------------------+
| FINISHED                                 |
| (retain_old=0 after first APP at new rx) |
+------------------------------------------+
~~~


# Overview of Security Goals

A complete security analysis of the EKU is outside the scope of this document. This appendix provides an informal description of the primary security goals that EKU is designed to achieve.

## Post-Compromise Security (PCS)

Extended Key Update supports post-compromise security under the assumptions described in {{scope}}. If an attacker temporarily compromises an endpoint and obtains the traffic keys in use before an Extended Key Update takes place, but the compromise does not persist during and after the EKU completes, the attacker cannot derive the new keying material established by EKU. This property follows from the use of fresh ephemeral key exchange material during each Extended Key Update. Compromise of prior traffic keys does not suffice to derive the new traffic keys. As a result, confidentiality of application data encrypted after the Extended Key Update is preserved even if the earlier traffic keys were exposed.

## Key Freshness and Cryptographic Independence

Each Extended Key Update derives new traffic keys from ephemeral key exchange material. This ensures strong separation between successive traffic keys:

* Compromise of prior traffic keys does not suffice to derive the new traffic keys established by an Extended Key Update.
* Compromise of one of traffic keys does not allow recovery of any earlier or later traffic keys.
* Application data protected under one of the traffic keys cannot be decrypted using keys from another.

## Elimination of Standard KeyUpdate

Once Extended Key Update has been negotiated for a session, peers rely exclusively on EKU rather than the standard TLS 1.3 KeyUpdate mechanism. Relying solely on Extended Key Update helps maintain PCS properties throughout the lifetime of the TLS session.

## Detecting Divergent Key State

As described in {{exported}}, Post-Handshake Certificate-Based Client
Authentication and Exported Authenticators can be used after an Extended Key Update to
detect that the endpoints derived different keys. Detection relies on the
CertificateVerify message, which is signed with a private key the attacker
does not hold, so validation fails and the interference is revealed. This assurance is
directional. Post-Handshake Authentication authenticates the client, so only the server
detects the divergence. An Exported Authenticator authenticates the endpoint that
produces it, so the peer validating it detects the divergence; assurance in both
directions requires an authenticator from each endpoint.
