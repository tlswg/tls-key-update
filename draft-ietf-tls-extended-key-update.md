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
{: #fig-key-update title="Extended Key Update Message Exchange."}

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
when `status == retry`.

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

# TLS 1.3 Exchange Steps

The following steps are taken by a TLS 1.3 implementation; the steps
executed with DTLS 1.3 differ slightly.

1. The initiator sends `ExtendedKeyUpdate(request)` carrying a
`KeyShareEntry`. While an extended key update is in progress, the
initiator MUST NOT initiate another key update.

2. Upon receipt, the responder sends `ExtendedKeyUpdate(response)`.
If the responder accepts the request, it sets `status=accepted` and
includes its own `KeyShareEntry`. If the responder declines, it sets
the appropriate status and omits the `KeyShareEntry`. While an extended
key update is in progress, the responder MUST NOT initiate another
key update.

3. Upon receipt of an `ExtendedKeyUpdate(response)` with
`status=accepted`, the initiator derives the new secrets from the
exchanged key shares. The subsequent
`ExtendedKeyUpdate(new_key_update)` is an intentionally empty structure
that triggers the switch to the new keying material.

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
`KeyShareEntry` MUST be rejected with `status=clashed` in the
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
 [ExtendedKeyUpdate(request     -------->
  (with key_share))]
                               <-------- [ExtendedKeyUpdate(response
                                           (accepted, with key_share))]
 [ExtendedKeyUpdate(new_key_update)]     -------->
                                         <--------
                                    [ExtendedKeyUpdate(new_key_update)]
~~~
{: #fig-key-update2 title="Extended Key Update Example Exchange."}

#  DTLS 1.3 Considerations

Due to the possibility of an `ExtendedKeyUpdate(new_key_update)` message
being lost and
thereby preventing the sender of the message
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

Protocols like DTLS-SRTP and DTLS-over-SCTP utilize TLS or DTLS for key
establishment but repurpose some of the keying material for their own
purpose. These protocols use the TLS exporter defined in
{{Section 7.5 of I-D.ietf-tls-rfc8446bis}}.

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
Matthijs van Duin, Rifaat Shekh-Yusef, Joe Birr-Pixton and Thom Wiggers
for their review comments.
