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
  RFC9325:
  RFC7296:
  RFC7624:
  I-D.ietf-tls-hybrid-design:
  I-D.ietf-tls-keylogfile:
  RFC5746:
  ANSSI-DAT-NT-003:
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

Security guidance from national agencies, such as ANSSI (France), recommends the
periodic renewal of cryptographic keys during long-lived sessions to limit the
impact of key compromise. This approach encourage designs designs that force an
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

The proposed extension is applicable to both TLS 1.3 and DTLS 1.3. For clarity,
the term "TLS" is used throughout this document to refer to both protocols unless
otherwise specified.

# Terminology and Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119 {{RFC2119}}.

To distinguish the key update procedure defined in {{I-D.ietf-tls-rfc8446bis}}
from the key update procedure specified in this document, we use the terms
"standard key update" and "extended key update", respectively.


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
=======
If the client and server agree to use the extended key update mechanism,
the standard key update MUST NOT be used. In this case, the extended
key update fully replaces the standard key update functionality.

Implementations that receive a classic KeyUpdate message after successfully
negotiating the Extended Key Update functionality MUST terminate the
connection with an "unexpected_message" alert.

The extended key update handshake message exchange used to perform an update
of cryptographic keys. This key update process can be sent by either
peer after it has sent a Finished message.  Implementations that
receive a ExtendedKeyUpdateRequest message prior to receiving a Finished
message MUST terminate the connection with an "unexpected_message"
alert.

The KeyShareEntry in the ExtendedKeyUpdateRequest message and in the
ExtendedKeyUpdateResponse message MUST be the same
algorithm mutually supported by the client and server during the initial
handshake. An implementation that receives an algorithm not previously
negotiated MUST terminate the connection with an "illegal_parameter" alert.

{{fig-key-update}} shows the interaction graphically.
First, support for the functionality in this specification
is negotiated in the ClientHello and the EncryptedExtensions
messages. Then, the ExtendedKeyUpdate exchange is sent to
update the application traffic secrets.

The extended key update exchange is performed between the initiator and the
responder whereby the initiator may be the TLS client or the TLS server.

~~~
       Client                                           Server

Key  ^ ClientHello
Exch | + key_share
     | + signature_algorithms
     v + extended_key_update       -------->
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
[ExtendedKeyUpdateRequest]N    -------->
                               <--------  [ExtendedKeyUpdateResponse]N
            [NewKeyUpdate]N    -------->
                               <--------  [NewKeyUpdate]N
                                  ...
       [Application Data]N+1   <------->  [Application Data]N+1

Legend:

        Indicates noteworthy extensions sent in the
        previously noted message.

-       Indicates optional or situation-dependent
        messages/extensions that are not always sent.

    () Indicates messages protected using keys
    derived from a client_early_traffic_secret.

    {} Indicates messages protected using keys
    derived from a [sender]_handshake_traffic_secret.

    []N Indicates messages protected using keys
    derived from [sender]_application_traffic_secret_N.

~~~
{: #fig-key-update title="Extended Key Update Message Exchange."}

The structure of the ExtendedKeyUpdate message is shown below.

~~~
struct {
  KeyShareEntry key_share;
} ExtendedKeyUpdateRequest;

enum {
  accepted(0),
  retry(1),
  rejected(2),
  clashed(3),
  (255)
} ExtendedKeyUpdateResponseStatus;

struct {
  ExtendedKeyUpdateResponseStatus status;
  select (ExtendedKeyUpdateResponse.status) {
     case accepted: KeyShareEntry key_share;
     case retry: uint8 delay;
  }
} ExtendedKeyUpdateResponse;

struct {
} NewKeyUpdate;
~~~

key_share:  Key share information.  The contents of this field
  are determined by the specified group and its corresponding
  definition. The structures are defined in {{I-D.ietf-tls-rfc8446bis}}.

status:  Response to ExtendedKeyUpdateRequest. This status field indicates
  whether responder accepted or declined Extended Key Update Request.

delay:  Delay in seconds for the initiator to retry the request.

There are three rejection reasons defined:

1. `retry`: request was declined temporarily as responder is too busy.
In this case ExtendedKeyUpdateResponse contains delay in seconds for initiator
to retry. Initiator MUST NOT retry within this interval and SHOULD retry after
it lapsed. Note that responder MAY apply an overall rate limit to extended key
update that would not be specific to given TLS session. If initiator cannot
proceed without immediate Extended Key Update it MUST terminate the connection
with TLS alert "extended_key_update_required" (alert number TBD).

2. `rejected`: request was declined permanently. Initiator MUST NOT retry and
if it cannot proceed without Extended Key Update it MUST terminate the
connection with alert "extended_key_update_required" (alert number TBD).

3. `clashed`: request was declined because responder already initiated its own
extended key update.

The exchange has the following steps:

1. Initiator sends a ExtendedKeyUpdateRequest message, which contains
a key share. While an extended key update is in progress, the initiator
MUST NOT initiate further key updates.

2. On receipt of the ExtendedKeyUpdateRequest message, the responder
sends the ExtendedKeyUpdateResponse message. If the responder accepts the
request, it sets the status to `accepted` and includes its own key share.
If the responder declines the request, it sets the status accordingly and
does not include the key share. While an extended key update is in progress,
the responder MUST NOT initiate further key updates.

3. On receipt of the ExtendedKeyUpdateResponse message with `accepted` status,
the initiator is able to derive a secret key based on the exchanged key shares.
The NewKeyUpdate message is intentionally an empty structure that triggers
the transition to new keying material.

5. On receipt of the NewKeyUpdate message by the responder, it MUST update
its receive keys. In response, the responder transmits a NewKeyUpdate message
and MUST update its sending keys.

6. After receiving the NewKeyUpdate message from the responder, the initiator
MUST update its traffic keys and MUST send all its traffic using the next
generation of keys.

Both sender and receiver MUST encrypt their NewKeyUpdate messages with
the old keys. Both sides MUST ensure that the NewKeyUpdate encrypted
with the old key is received before accepting any messages encrypted
with the new key.

If TLS peers independently initiate the extended key update
procedure and the requests cross in flight, the ExtendedKeyUpdateRequest
message with the lower lexicographic order for the key_exchange value
in the KeyShareEntry will be rejected by the responder using `clashed` status
in ExtendedKeyUpdateResponse message. This approach prevents each side incrementing
keys by two generations.

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

# Updating Traffic Secrets {#key_update}

When the extended key update message exchange is completed both peers
have successfully updated their application traffic secrets. The
key derivation function described in this document is used to perform
this update.

The design of the key derivation function for computing the next generation
of application_traffic_secret is motivated by the desire to include

* a secret derived from the (EC)DHE exchange (or from the hybrid key exchange
/ PQ-KEM exchange),
* a secret that allows the new key exchange to be cryptographally bind
the previously established secret to the newly derived secret,
* the concatenation of the ExtendedKeyUpdateRequest and the
ExtendedKeyUpdateResponse messages, which contain the key shares, binding
the encapsulated shared secret ciphertext to IKM in case of hybrid key
exchange, providing MAL-BIND-K-CT security (see {{CDM23}}), and
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
             |                ExtendedKeyUpdateRequest ||
             |                ExtendedKeyUpdateResponse)
             |                = client_application_traffic_secret_N+1
             |
             +-----> Derive-Secret(., "s ap traffic2",
             |                ExtendedKeyUpdateRequest ||
             |                ExtendedKeyUpdateResponse)
             |                = server_application_traffic_secret_N+1
             |
             +-----> Derive-Secret(., "exp master2",
             |                ExtendedKeyUpdateRequest ||
             |                ExtendedKeyUpdateResponse)
             |                = exporter_master_secret_N+1
             |
             +-----> Derive-Secret(., "res master2",
             |                ExtendedKeyUpdateRequest ||
             |                ExtendedKeyUpdateResponse))
                              = resumption_master_secret_N+1
~~~

During the initial handshake the Master Secret is generated, see
{{Section 7.1 of I-D.ietf-tls-rfc8446bis}}. Since the Master Secret
is discarded during the key derivation procedure, a derived value is
stored. This value then serves as input to another key derivation step
that takes the (EC)DHE-established value as a second parameter into
account.

The traffic keys are re-derived from client_application_traffic_secret_N+1
and server_application_traffic_secret_N+1, as described in
{{Section 7.3 of I-D.ietf-tls-rfc8446bis}}.

Once client_/server_application_traffic_secret_N+1 and its associated
traffic keys have been computed, implementations SHOULD delete
client_/server_application_traffic_secret_N and its associated
traffic keys as soon as possible. Note: The
client_/server_application_traffic_secret_N and its associated
traffic keys can only be deleted after receiving the NewKeyUpdate message.

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

# Example

{{fig-key-update}} shows the interaction between a TLS 1.3 client
and server graphically. This section shows an example message exchange
where a client updates its sending keys.

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
 [ExtendedKeyUpdateRequest     -------->
  (with key_share)]
                               <-------- [ExtendedKeyUpdateResponse
                                           (with key_share)]
 [NewKeyUpdate]                -------->
                               <-------- [NewKeyUpdate]
~~~
{: #fig-key-update2 title="Extended Key Update Message Exchange."}

#  DTLS 1.3 Considerations

Due to the possibility of a NewKeyUpdate message being lost and
thereby preventing the sender of the NewKeyUpdate message
from updating its keying material, receivers MUST retain the
pre-update keying material until receipt and successful decryption
of a message using the new keys.

Due to loss and/or reordering, DTLS 1.3 implementations may receive a
record with an older epoch than the current one. They SHOULD attempt to
process those records with that epoch but MAY opt to discard
such out-of-epoch records.

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

1. `CLIENT_TRAFFIC_SECRET_N+1`: identifies the client_application_traffic_secret_N+1 in the key schedule

2. `SERVER_TRAFFIC_SECRET_N+1`: identifies the server_application_traffic_secret_N+1 in the key schedule

Similar to other entries in the SSLKEYLOGFILE, the label is followed by the
32-byte value of the Random field from the ClientHello message that
established the TLS connection, and the corresponding secret encoded in
hexadecimal.

SSLKEYLOGFILE entries for the extended key update MUST NOT be produced if
SSLKEYLOGFILE was not used for other secrets in the handshake.

Note that each successful Extended Key Update invalidates all previous SSLKEYLOGFILE
secrets including past iterations of `CLIENT_TRAFFIC_SECRET_` and
`SERVER_TRAFFIC_SECRET_`.

# Exporter

Protocols like DTLS-SRTP and DTLS-over-SCTP utilize TLS or DTLS for key establishment but repurpose
some of the keying material for their own purpose. These protocols use the TLS exporter defined in
{{Section 7.5 of I-D.ietf-tls-rfc8446bis}}.

Once the Extended Key Update mechanism is complete, such protocols would need to use the newly
derived key to generate Exported Keying Material (EKM) to protect packets. The "sk" derived in the
{{key_update}} will be used as the "Secret" in the exporter function, defined in
{{Section 7.5 of I-D.ietf-tls-rfc8446bis}}, to generate EKM, ensuring that the exported keying
material is aligned with the updated security context.

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

IANA is requested to add the following entries to the "TLS HandshakeType"
registry {{TLS-Ext-Registry}}.

### `extended_key_update_request` Message

*  Value: TBD2
*  Description: extended_key_update
*  DTLS-OK: Y
*  Reference: [This document]
*  Comment:

### `extended_key_update_response` Message

*  Value: TBD3
*  Description: extended_key_update_response
*  DTLS-OK: Y
*  Reference: [This document]
*  Comment:

### `new_key_update` Message

*  Value: TBD3
*  Description: new_key_update
*  DTLS-OK: Y
*  Reference: [This document]
*  Comment:

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
Matthijs van Duin, Rifaat Shekh-Yusef, Joe Birr-Pixton and Thom Wiggers for their review comments.
