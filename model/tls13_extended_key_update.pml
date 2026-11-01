/* TLS 1.3 EKU over ordered, reliable record delivery.
 * Response advances responder TX; finish advances initiator TX and responder
 * RX. There are no DTLS ACKs, losses, retransmissions, or CID messages.
 * Authentication contexts use the same explicit generation abstraction as
 * the DTLS profiles; see SPEC-MAPPING.md.
 */
#define TRANSPORT_TLS 1
#include "eku_protocol.pml"
